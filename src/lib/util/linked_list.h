/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef RRR_LINKED_LIST_H
#define RRR_LINKED_LIST_H

#include <stdlib.h>

#include "slow_noop.h"

#define RRR_LL_DID_DESTROY   0
#define RRR_LL_DESTROY_ERR   1
#define RRR_LL_DIDNT_DESTROY 2

#define RRR_LL_HEAD(type)                                      \
    type *ptr_first;                                           \
    type *ptr_last;                                            \
    int node_count                                             \

#define RRR_LL_HEAD_CXX_INIT                                   \
    ptr_first(NULL), ptr_last(NULL), node_count(0)

#define RRR_LL_NODE(type)                                      \
    type *ptr_prev;                                            \
    type *ptr_next                                             \

#define RRR_LL_NODE_CXX_INIT                                   \
    ptr_prev(NULL), ptr_next(NULL)

#define RRR_LL_NODE_INIT(node)                                 \
    node->ptr_prev = NULL;                                     \
    node->ptr_next = NULL                                      \

#define RRR_LL_VERIFY_HEAD(head)                               \
    do {if (                                                   \
        ((head)->ptr_first != NULL && (head)->ptr_last == NULL) ||       \
        ((head)->ptr_last != NULL && (head)->ptr_first == NULL) ||       \
        ((head)->ptr_first == NULL && (head)->node_count != 0) \
    ) {                                                        \
        RRR_BUG("Bug: Linked list head integrity error");      \
    }} while(0)                                                \

#define RRR_LL_VERIFY_NODE(head)                               \
    do {if (    (node->ptr_prev == NULL && (head)->ptr_first != node) || \
                (node->ptr_next == NULL && (head)->ptr_last != node) ||  \
                (node->ptr_prev != NULL && (head)->ptr_first == node) || \
                (node->ptr_next != NULL && (head)->ptr_last == node) ||  \
                (    (head)->ptr_first != node &&              \
                    (head)->ptr_last != node &&                \
                    (node->ptr_next == NULL || node->ptr_prev == NULL)   \
                )                                              \
        ) {                                                    \
            RRR_BUG("Bug: Linked list node integrity error");  \
        }                                                      \
    } while(0)                                                 \

#define RRR_LL_IS_EMPTY(head)                                  \
    ((head)->ptr_first == NULL)                                \

#define RRR_LL_COUNT(head)                                     \
    ((head)->node_count)                                       \

#define RRR_LL_DANGEROUS_CLEAR_HEAD(head)                      \
    (head)->ptr_first = NULL;                                  \
    (head)->ptr_last = NULL;                                   \
    (head)->node_count = 0                                     \

#define RRR_LL_REPLACE_NODE(target, source, type, replace_func)   \
    do {                                                       \
    if ((source)->ptr_next != NULL)                            \
        RRR_BUG("source had non-NULL ptr_next-pointer in RRR_LINKED_LIST_REPLACE_NODE\n");   \
    type *next_preserve = target->ptr_next;                    \
    type *prev_preserve = target->ptr_prev;                    \
    replace_func;                                              \
    target->ptr_next = next_preserve;                          \
    target->ptr_prev = prev_preserve;                          \
    } while (0)                                                \

#define RRR_LL_UNSHIFT(head,node) do {                         \
    (node)->ptr_next = NULL;                                   \
    (node)->ptr_prev = NULL;                                   \
    if ((head)->ptr_first == NULL) {                           \
        (head)->ptr_first = (node);                            \
        (head)->ptr_last = (node);                             \
    }                                                          \
    else {                                                     \
        (head)->ptr_first->ptr_prev = (node);                  \
        (node)->ptr_next = (head)->ptr_first;                  \
        (head)->ptr_first = (node);                            \
    }                                                          \
    (head)->node_count++; } while (0)                          \

// Avoid warning in static code analysis by checking both first and last
// pointer for NULL. The tool does not always understand that they are both
// always either NULL or not NULL
#define RRR_LL_APPEND(head,node) do {                          \
    (node)->ptr_next = NULL;                                   \
    (node)->ptr_prev = NULL;                                   \
    if ((head)->ptr_first == NULL || (head)->ptr_last == NULL) {   \
        (head)->ptr_first = (node);                            \
        (head)->ptr_last = (node);                             \
    }                                                          \
    else {                                                     \
        (head)->ptr_last->ptr_next = (node);                   \
        (node)->ptr_prev = (head)->ptr_last;                   \
        (head)->ptr_last = (node);                             \
    }                                                          \
    (head)->node_count++; } while (0)                          \

#define RRR_LL_PUSH(head,node)                                 \
    RRR_LL_APPEND(head,node)                                   \

#define RRR_LL_FIRST(head)                                     \
    ((head)->ptr_first)                                        \

#define RRR_LL_LAST(head)                                      \
    ((head)->ptr_last)                                         \

#define RRR_LL_DESTROY(head, type, destroy_func) do {          \
    type *node = (head)->ptr_first;                            \
    type *next = NULL;                                         \
    while (node != NULL) {                                     \
        next = node->ptr_next;                                 \
        destroy_func;                                          \
        (head)->node_count--;                                  \
        node = next;                                           \
    }                                                          \
    (head)->ptr_first = (head)->ptr_last = NULL;               \
    } while (0)                                                \

#define __RRR_LL_ITERATE_REMOVE_NODE(head)                     \
        if ((head)->ptr_first == node) {                       \
            (head)->ptr_first = next;                          \
        }                                                      \
        if ((head)->ptr_last == node) {                        \
            (head)->ptr_last = prev;                           \
        }                                                      \
        if (next != NULL) {                                    \
            next->ptr_prev = prev;                             \
        }                                                      \
        if (prev != NULL) {                                    \
            prev->ptr_next = next;                             \
        }                                                      \
        (head)->node_count--                                   \

#define RRR_LL_REMOVE_NODE_IF_EXISTS(head, type, find, destroy_func) do {   \
    type *node = (head)->ptr_first;                            \
    type *next = NULL;                                         \
    type *prev = NULL;                                         \
    while (node != NULL) {                                     \
        next = node->ptr_next;                                 \
        if (node == find) {                                    \
            destroy_func;                                      \
            __RRR_LL_ITERATE_REMOVE_NODE(head);                \
            find = NULL;                                       \
            break;                                             \
        }                                                      \
        prev = node;                                           \
        node = next;                                           \
    }} while (0)                                               \

#define RRR_LL_REMOVE_NODE_NO_FREE(head, find) do {            \
    if ((find)->ptr_prev == NULL) {                            \
        (head)->ptr_first = (find)->ptr_next;                  \
    }                                                          \
    else {                                                     \
        (find)->ptr_prev->ptr_next = (find)->ptr_next;         \
    }                                                          \
    if ((find)->ptr_next == NULL) {                            \
        (head)->ptr_last = (find)->ptr_prev;                   \
    }                                                          \
    else {                                                     \
        (find)->ptr_next->ptr_prev = (find)->ptr_prev;         \
    }                                                          \
    (head)->node_count--; } while(0)                           \

#define RRR_LL_SHIFT(head)                                     \
    RRR_LL_FIRST(head);    /* Shift is used with assignment */ \
    do {if ((head)->ptr_first != NULL) {                       \
        if ((head)->ptr_last == (head)->ptr_first) {           \
            (head)->ptr_first = NULL;                          \
            (head)->ptr_last = NULL;                           \
        } else {                                               \
            (head)->ptr_first = (head)->ptr_first->ptr_next;   \
            (head)->ptr_first->ptr_prev = NULL;                \
        } (head)->node_count--;                                \
    }} while (0)                                               \

#define RRR_LL_POP(head)                                       \
    RRR_LL_LAST(head);    /* Pop is used with assignment */    \
    do {if ((head)->ptr_last != NULL) {                        \
        if ((head)->ptr_first == (head)->ptr_last) {           \
            (head)->ptr_last = NULL;                           \
            (head)->ptr_first = NULL;                          \
        } else {                                               \
            (head)->ptr_last = (head)->ptr_last->ptr_prev;     \
            (head)->ptr_last->ptr_next = NULL;                 \
        } (head)->node_count--;                                \
    }} while (0)                                               \


#define RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(target,source)      \
    do {if ((source)->ptr_first != NULL) {                     \
            if ((target)->ptr_last != NULL) {                  \
                (target)->ptr_last->ptr_next = (source)->ptr_first;   \
            }                                                  \
            (source)->ptr_first->ptr_prev = (target)->ptr_last;\
            (target)->ptr_last = (source)->ptr_last;           \
            if ((target)->ptr_first == NULL) {                 \
                (target)->ptr_first = (source)->ptr_first;     \
            }                                                  \
            (source)->ptr_first = (source)->ptr_last = NULL;   \
            (target)->node_count += (source)->node_count;      \
            (source)->node_count = 0;                          \
        }} while(0)                                            \

#define RRR_LL_ITERATE_BEGIN_AT(head, type, at, reverse) do {  \
    type *node = (at);                                         \
    type *prev = NULL; (void)(prev);                           \
    type *next = NULL;                                         \
    int linked_list_iterate_stop = 0;                          \
    int linked_list_immediate_break = 0;                       \
    int linked_list_ret_tmp = 0; (void)(linked_list_ret_tmp);  \
    int linked_list_reverse = reverse;                         \
    while (node != NULL && linked_list_iterate_stop != 1) {    \
        int linked_list_iterate_destroy = 0;                   \
        do {                                                   \
            next = node->ptr_next;                             \
            prev = node->ptr_prev                              \

#define RRR_LL_ITERATE_BEGIN_EITHER(head, type, reverse)       \
    RRR_LL_ITERATE_BEGIN_AT(head, type, (reverse != 0 ? (head)->ptr_last : (head)->ptr_first), reverse)   \

#define RRR_LL_ITERATE_BEGIN(head, type)                       \
    RRR_LL_ITERATE_BEGIN_AT(head, type, (head)->ptr_first, 0)  \

#define RRR_LL_ITERATE_BEGIN_REVERSE(head, type)               \
    RRR_LL_ITERATE_BEGIN_AT(head, type, (head)->ptr_last, 1)   \

#define RRR_LL_ITERATE_INSERT(head, new_node) do {             \
    (head)->node_count++;                                      \
    (new_node)->ptr_prev = node->ptr_prev;                     \
    (new_node)->ptr_next = node;                               \
    node->ptr_prev = (new_node);                               \
    if (prev == NULL) {                                        \
        (head)->ptr_first = new_node;                          \
    }                                                          \
    else {                                                     \
        prev->ptr_next = new_node;                             \
    }} while (0)                                               \

#define RRR_LL_ITERATE_IS_FIRST()                              \
        (prev == NULL)                                         \

#define RRR_LL_ITERATE_IS_LAST()                               \
        (next == NULL)                                         \

#define RRR_LL_ITERATE_SET_DESTROY()                           \
        linked_list_iterate_destroy = 1                        \

#define RRR_LL_ITERATE_LAST()                                  \
        linked_list_iterate_stop = 1                           \

#define RRR_LL_ITERATE_NEXT()                                  \
        break                                                  \

#define RRR_LL_ITERATE_BREAK()                                 \
        linked_list_immediate_break = 1; break                 \

#define __RRR_LL_ITERATE_END(no_check_destroy)                 \
        } while (0);                                           \
        if (linked_list_immediate_break != 0) {                \
            break;                                             \
        }                                                      \
        if (no_check_destroy == 0 && linked_list_iterate_destroy != 0) {                \
            RRR_BUG("RRR_LL_SET_DESTROY was used without destroy "                      \
                    "function, must use RRR_LL_ITERATE_END_CHECK_DESTROY instead\n");   \
        }                                                      \
        if (linked_list_reverse) {                             \
            node = prev;                                       \
        }                                                      \
        else {                                                 \
            node = next;                                       \
        }                                                      \
    }} while(0)                                                \

#define RRR_LL_ITERATE_END()                                   \
        __RRR_LL_ITERATE_END(0)                                \

#define RRR_LL_ITERATE_END_CHECK_DESTROY_WRAP_LOCK(head, destroy_func, destroy_err, lock, unlock, lock_err)   \
        } while (0);                                           \
        if (linked_list_immediate_break != 0) {                \
            break;                                             \
        }                                                      \
        if (linked_list_iterate_destroy) {                     \
            linked_list_ret_tmp = destroy_func;                \
            if (linked_list_ret_tmp == RRR_LL_DESTROY_ERR) { destroy_err; }   \
            if (linked_list_ret_tmp == RRR_LL_DID_DESTROY) {   \
                if ((lock) != 0) { lock_err; }                 \
                __RRR_LL_ITERATE_REMOVE_NODE(head);            \
                if ((unlock) != 0) { lock_err; }               \
            }                                                  \
            linked_list_iterate_destroy = 0;                   \
        }                                                      \
        if (linked_list_reverse) {                             \
            node = prev;                                       \
        }                                                      \
        else {                                                 \
            node = next;                                       \
        }                                                      \
    }} while(0)                                                \

#define RRR_LL_ITERATE_END_CHECK_DESTROY(head, destroy_func)   \
    RRR_LL_ITERATE_END_CHECK_DESTROY_WRAP_LOCK(head, destroy_func, rrr_slow_noop(), rrr_slow_noop(), rrr_slow_noop(), rrr_slow_noop())   \

#define RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(destroy_func)   \
            if (linked_list_iterate_destroy) {                 \
                destroy_func;                                  \
                linked_list_iterate_destroy = 0;               \
            }                                                  \
            __RRR_LL_ITERATE_END(1)                            \

#define RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(head)         \
    RRR_LL_ITERATE_END_CHECK_DESTROY_WRAP_LOCK(head, rrr_slow_noop(), rrr_slow_noop(), rrr_slow_noop(), rrr_slow_noop(), rrr_slow_noop())   \

#endif /* RRR_LINKED_LIST_H */
