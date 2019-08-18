/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#define RRR_LINKED_LIST_DID_DESTROY		0
#define RRR_LINKED_LIST_DESTROY_ERR		1
#define RRR_LINKED_LIST_DIDNT_DESTROY	2

#define RRR_LINKED_LIST_HEAD(type)						\
	type *ptr_first;									\
	type *ptr_last;										\
	int node_count

#define RRR_LINKED_LIST_NODE(type)						\
	type *ptr_prev;										\
	type *ptr_next

#define RRR_LINKED_LIST_IS_EMPTY(head)					\
	((head)->ptr_first == NULL)

#define RRR_LINKED_LIST_COUNT(head)						\
	((head)->node_count)

#define RRR_LINKED_LIST_DANGEROUS_CLEAR_HEAD(head)		\
	(head)->ptr_first = NULL;							\
	(head)->ptr_last = NULL;							\
	(head)->node_count = 0

#define RRR_LINKED_LIST_REPLACE_NODE(target, source, type, replace_func)	\
	do {																	\
	if (source->ptr_next != NULL)											\
		VL_BUG("source had non-NULL ptr_next-pointer in RRR_LINKED_LIST_REPLACE_NODE\n"); \
	type *next_preserve = target->ptr_next;									\
	type *prev_preserve = target->ptr_next;									\
	replace_func;															\
	target->ptr_next = next_preserve;										\
	target->ptr_prev = prev_preserve;										\
	} while (0)

#define RRR_LINKED_LIST_PUSH(head,node) do {			\
	(node)->ptr_next = NULL;							\
	(node)->ptr_prev = NULL;							\
	if ((head)->ptr_first == NULL) {					\
		(head)->ptr_first = (node);						\
		(head)->ptr_last = (node);						\
	}													\
	else {												\
		(head)->ptr_first->ptr_prev = (node);			\
		(node)->ptr_next = (head)->ptr_first;			\
		(head)->ptr_first = (node);						\
	}													\
	(head)->node_count++; } while (0)

#define RRR_LINKED_LIST_APPEND(head,node) do {			\
	(node)->ptr_next = NULL;							\
	(node)->ptr_prev = NULL;							\
	if ((head)->ptr_first == NULL) {					\
		(head)->ptr_first = (node);						\
		(head)->ptr_last = (node);						\
	}													\
	else {												\
		(head)->ptr_last->ptr_next = (node);			\
		(node)->ptr_prev = (head)->ptr_last;			\
		(head)->ptr_last = (node);						\
	}													\
	(head)->node_count++; } while (0)


#define RRR_LINKED_LIST_DESTROY(head, type, destroy_func) do {	\
	type *node = (head)->ptr_first;								\
	type *next = NULL;											\
	while (node != NULL) {										\
		next = node->ptr_next;									\
		destroy_func;											\
		(head)->node_count--;									\
		node = next;											\
	}															\
	(head)->ptr_first = (head)->ptr_last = NULL;				\
	} while (0)

#define __RRR_LINKED_LIST_ITERATE_REMOVE_NODE(head)	\
		if ((head)->ptr_first == node) {			\
			(head)->ptr_first = next;				\
		}											\
		if ((head)->ptr_last == node) {				\
			(head)->ptr_last = prev;				\
		}											\
		if (next != NULL) {							\
			next->ptr_prev = prev;					\
		}											\
		if (prev != NULL) {							\
			prev->ptr_next = next;					\
		}											\
		(head)->node_count--

#define RRR_LINKED_LIST_REMOVE_NODE(head, type, find, destroy_func) do {	\
	type *node = (head)->ptr_first;											\
	type *next = NULL;														\
	type *prev = NULL;														\
	while (node != NULL) {													\
		next = node->ptr_next;												\
		if (node == find) {													\
			destroy_func;													\
			__RRR_LINKED_LIST_ITERATE_REMOVE_NODE(head);					\
			break;															\
		}																	\
		node = next;														\
	}} while (0)

#define RRR_LINKED_LIST_ITERATE_BEGIN(head, type) do {			\
	type *node = (head)->ptr_first;								\
	type *prev = NULL; (void)(prev);							\
	type *next = NULL;											\
	int linked_list_iterate_stop = 0;							\
	int linked_list_ret_tmp = 0; (void)(linked_list_ret_tmp);	\
	while (node != NULL && linked_list_iterate_stop != 1) {		\
		int linked_list_iterate_destroy = 0;					\
		next = node->ptr_next

#define RRR_LINKED_LIST_SET_DESTROY()						\
		linked_list_iterate_destroy = 1

#define RRR_LINKED_LIST_SET_STOP()							\
		linked_list_iterate_stop = 1

#define RRR_LINKED_LIST_ITERATE_END()															\
		if (linked_list_iterate_destroy != 0) {													\
			VL_BUG("RRR_LINKED_LIST_SET_DESTROY was used without destroy "						\
					"function, must use RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY instead\n");	\
		}																						\
		prev = node;																			\
		node = next;																			\
	}} while(0)

#define RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY_WRAP_LOCK(head, destroy_func, destroy_err, lock, unlock, lock_err) \
		if (linked_list_iterate_destroy) {														\
			linked_list_ret_tmp = destroy_func;													\
			if (linked_list_ret_tmp == RRR_LINKED_LIST_DESTROY_ERR) { destroy_err; }			\
			if (linked_list_ret_tmp == RRR_LINKED_LIST_DID_DESTROY) {							\
				if ((lock) != 0) { lock_err; }													\
				__RRR_LINKED_LIST_ITERATE_REMOVE_NODE(head);									\
				if ((unlock) != 0) { lock_err; }												\
			}																					\
			else {																				\
				prev = node;																	\
			}																					\
			linked_list_iterate_destroy = 0;													\
		}																						\
		else {																					\
			prev = node;																		\
		}																						\
		node = next;																			\
	}} while(0)

#define RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY(head, destroy_func)	\
	RRR_LINKED_LIST_ITERATE_END_CHECK_DESTROY_WRAP_LOCK(head, destroy_func, asm(""), 0, 0, asm(""))

#endif /* RRR_LINKED_LIST_H */
