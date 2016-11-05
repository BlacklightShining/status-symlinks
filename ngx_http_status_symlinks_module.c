/*
 *
 * status-symlinks -- make nginx interpret symlinks as HTTP responses
 * Copyright (C) 2016  Blacklight Shining <blacklightshining@derpymail.org>
 *                     (PGP key C7106095)
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this module.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "ngx_config.h"
#include "ngx_core.h"
#include "ngx_http.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>

static ngx_int_t ngx_http_status_symlinks_handler(ngx_http_request_t *);
static void *ngx_http_status_symlinks_create_conf(ngx_conf_t *);
static char *ngx_http_status_symlinks_merge_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_status_symlinks_init(ngx_conf_t *);

typedef struct
{
    ngx_flag_t enabled;
} ngx_http_status_symlinks_conf_t;

static ngx_command_t ngx_http_status_symlinks_commands[] =
{
    {
        .name = ngx_string("status_symlinks"),
        .type = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
            | NGX_CONF_FLAG,
        .set = ngx_conf_set_flag_slot,
        .conf = NGX_HTTP_LOC_CONF_OFFSET,
        .offset = offsetof(ngx_http_status_symlinks_conf_t, enabled),
        .post = NULL
    },
    ngx_null_command
};

ngx_http_module_t ngx_http_status_symlinks_module_context =
{
    .preconfiguration = NULL,
    .postconfiguration = &ngx_http_status_symlinks_init,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = &ngx_http_status_symlinks_create_conf,
    .merge_loc_conf = &ngx_http_status_symlinks_merge_conf,
};

ngx_module_t ngx_http_status_symlinks_module =
{
    NGX_MODULE_V1,
    .ctx = &ngx_http_status_symlinks_module_context,
    .commands = ngx_http_status_symlinks_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_status_symlinks_handler(ngx_http_request_t *request)
{
    ngx_log_t *log = request->connection->log;
    ngx_http_status_symlinks_conf_t *config =
        ngx_http_get_module_loc_conf(request, ngx_http_status_symlinks_module);

    if (!config || !config->enabled)
        return NGX_DECLINED;

    ngx_str_t file_path;
    {
        // This function is undocumented. The static-file handler uses it,
        // though, and it sounds like exactly what we want, so…!
        // I'll be honest; I don't understand the third argument (beyond it
        // being an outpointer that gets written to without a nullcheck…). It
        // doesn't seem that we have any use for it, though.
        size_t _;
        u_char *file_path_end =
            ngx_http_map_uri_to_path(request, &file_path, &_, 0);
        if (!file_path_end)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        file_path.len = file_path_end - file_path.data;
    }
    // We use -ftrapv for generating traps on signed integer overflow, but
    // there's no such option for unsigned. So! Check ALL the operations! YAY!!
    if (file_path.len > SIZE_MAX - 1)
    {
        ngx_log_error(NGX_LOG_CRIT, log, EOVERFLOW,
            "ngx_http_map_uri_to_path() returned a path with length %zu--"
            "too close to SIZE_MAX (%zu)",
            file_path.len, SIZE_MAX);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    char *file_path_cstr = ngx_palloc(request->pool, file_path.len + 1);
    if (!file_path_cstr)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_memcpy(file_path_cstr, file_path.data, file_path.len);
    file_path_cstr[file_path.len] = '\0';

    struct stat file_stats;
    if (lstat(file_path_cstr, &file_stats) < 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, errno,
            "lstat() \"%s\" failed", file_path_cstr);
        switch (errno)
        {
            // Decline instead of returning 404|403s. I dunno; maybe some other
            // module will handle this without looking for a file with that
            // name. If not, the static handler will return the error.
            case ENOENT:
            case ENOTDIR:
            case ELOOP:
            case ENAMETOOLONG:
            case EACCES:
                return NGX_DECLINED;
            case ENOMEM:
            case EFAULT:
            case EOVERFLOW:
            default:
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    // Don't want to allocate several gibibytes of memory only to find that the
    // file isn't actually a symlink, so better check that up here, too.
    if (!S_ISLNK(file_stats.st_mode))
        return NGX_DECLINED;
    size_t symlink_target_stat_len = file_stats.st_size;
    if (symlink_target_stat_len > SIZE_MAX - 1)
    {
        ngx_log_error(NGX_LOG_CRIT, log, EOVERFLOW,
            "stat() returned a file size of %zu--too close to SIZE_MAX (%zu)",
            symlink_target_stat_len, SIZE_MAX);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    // +1 for the trailing nullbyte
    char *symlink_target = ngx_palloc(request->pool,
        symlink_target_stat_len + 1);
    if (!symlink_target)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ssize_t symlink_target_len = readlink(file_path_cstr, symlink_target,
        symlink_target_stat_len + 1);
    if (symlink_target_len < 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, errno,
            "readlink() \"%s\" failed", file_path_cstr);
        switch (errno)
        {
            // Need to handle not-a-symlink (one of EINVAL's meanings) again,
            // just in case the symlink got replaced after our lstat().
            case EINVAL:
            case ENOENT:
            case ENOTDIR:
            case ELOOP:
            case ENAMETOOLONG:
            case EACCES:
                return NGX_DECLINED;
            case ENOMEM:
            case EFAULT:
            case EIO:
            default:
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    ngx_log_error(NGX_LOG_DEBUG_HTTP, log, 0,
        "http filename: \"%s\"", file_path_cstr);
    // This check needs to happen BEFORE we add the trailing nullbyte, else
    // we'll be writing one byte beyond the buffer.
    if ((size_t) symlink_target_len > symlink_target_stat_len)
    {
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "http status_symlinks link length grew between lstat() and "
            "readlink() (previous length: %zd); retrying",
            symlink_target_len);
        // @whoever's modifying the document root right now: You wanna race? :D
        // (Internal-redirect to the same URI—nginx has a limit on these, so we
        // won't get stuck in a loop.)
        return ngx_http_internal_redirect(request, &request->uri,
            &request->args);
    }
    symlink_target[symlink_target_len] = '\0';

    // lrwxrwxrwx ... /var/www/foo -> 301:https://rkyidv.example/long-path/foo
    //                                ^~~~
    if (symlink_target_len < 4)
        return NGX_DECLINED;
    {
        // Types are different; use a temporary variable until we're done
        // bounds-checking. Anonymous scope 'cause we're not gonna use it after
        // that.
        ngx_int_t http_status = ngx_atoi((u_char *) symlink_target, 3);
        if (symlink_target[3] != ':' || http_status < 100 || http_status >= 600)
            return NGX_DECLINED;
        request->headers_out.status = http_status;
    }
    ngx_log_error(NGX_LOG_DEBUG_HTTP, log, 0,
        "http status_symlinks link target: \"%s\"", symlink_target);
    // These only take a small, fixed number of arguments. If support for more
    // status codes is added later, `args` can simply be expanded as necessary.
    ngx_str_t args[2] = {ngx_null_string, ngx_null_string};
    {
        u_char *arg_start = (u_char *) &symlink_target[4], *arg_end = NULL;
        u_char *symlink_target_end =
            (u_char *) &symlink_target[symlink_target_len];
        for (size_t i = 0; i < sizeof(args) / sizeof(args[0]); ++i)
        {
            args[i].data = arg_start;
            if ((arg_end = ngx_strlchr(arg_start, symlink_target_end, ';')))
            {
                args[i].len = arg_end - arg_start;
                *arg_end = '\0';
            }
            else
            {
                args[i].len = symlink_target_end - arg_start;
                break;
            }
            arg_start = arg_end + 1;
        }
    }
    switch (request->headers_out.status)
    {
        case 204:
            request->header_only = 1;
            break;
        case 301:
        case 302:
        case 303:
        case 307:
        case 308:
            request->header_only = 1;
            ngx_table_elt_t *location_header = request->headers_out.location
                = ngx_list_push(&request->headers_out.headers);
            if (!location_header)
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            ngx_str_set(&location_header->key, "Location");
            location_header->value = args[0];
            location_header->hash = 1;
            break;
        case 403:
        case 404:
        case 410:
        case 451:
            if (request->headers_out.status == 451 && args[1].len)
            {
                ngx_table_elt_t *link_header =
                    ngx_list_push(&request->headers_out.headers);
                if (!link_header)
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                ngx_str_set(&link_header->key, "Link");
                link_header->value = args[1];
                link_header->hash = 1;
            }
            if (!args[0].len)
                request->header_only = 1;
            break;
        default:
            return NGX_DECLINED;
    }

    return ngx_http_send_header(request);
}

static void *ngx_http_status_symlinks_create_conf(ngx_conf_t *ngx_conf)
{
    ngx_http_status_symlinks_conf_t *config =
        ngx_palloc(ngx_conf->pool, sizeof(ngx_http_status_symlinks_conf_t));
    if (!config)
        return NULL;

    config->enabled = NGX_CONF_UNSET;

    return config;
}

static char *ngx_http_status_symlinks_merge_conf(ngx_conf_t *_,
        void *_parent, void *_child)
{
    ngx_http_status_symlinks_conf_t *parent = _parent, *child = _child;

    ngx_conf_merge_value(child->enabled, parent->enabled, 0);

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_status_symlinks_init(ngx_conf_t *config)
{
    ngx_http_core_main_conf_t *main_config =
        ngx_http_conf_get_module_main_conf(config, ngx_http_core_module);
    if (!main_config)
        return NGX_ERROR;
    ngx_http_handler_pt *handler =
        ngx_array_push(&main_config->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (!handler)
        return NGX_ERROR;
    *handler = ngx_http_status_symlinks_handler;
    return NGX_OK;
}
