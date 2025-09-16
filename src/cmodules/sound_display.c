/*
 * Licensed under RRR MODULE LICENSE VERSION 1.
 *
 * Copyright 2025 Atle Solbakken <atle@goliathdns.no>
 *
 * This file may be expanded, modified and customized and re-licensed under
 * the terms of either
 *  - GPL version 3 or later
 *  or
 *  - RRR MODULE LICENCE VERSION 1 or later
 *  .
 *
 * The new author(s) own(s) full copyright of the newly licensed file. A
 * new copyright notice appropriate for one of the above mentioned licenses
 * must be applied in the place of this copyright notice.
 *
 * When re-licensing the file, this copyright notice, including reference
 * to the original author MUST be removed.
 */

#include <stdlib.h>
#include <errno.h>
#include <gtk/gtk.h>

#include "cmodule.h"
#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/rrr_strerror.h"
#include "../lib/helpers/nullsafe_str.h"
#include "../lib/array.h"
#include "../lib/map.h"
#include "../lib/util/rrr_time.h"

// #define DEBUG_BOXES

#define PHRASE_EXPIRATION_HARD_US (30 * 1000 * 1000)
#define PHRASE_EXPIRATION_SOFT_US (1 * 1000 * 1000)

struct sound_display_data {
	GtkWidget *window;
	GtkWidget *hbox;
	GtkWidget *grid;
	GtkWidget *text;
	struct rrr_map phrase_full;
	int phrase_pos;
	uint64_t phrase_expiration;
	int do_stop;
};

void gloop(void) {
	while (g_main_context_pending(NULL)) {
		g_main_context_iteration(NULL, FALSE);
	}
}

static void on_closed(GtkApplication *app, gpointer *arg) {
	struct sound_display_data *data = (struct sound_display_data *) arg;

	(void)(app);

	RRR_MSG_0("Sound display lost connection to X server\n");

	data->do_stop = 1;
}

static void on_destroy(GtkApplication *app, gpointer *arg) {
	struct sound_display_data *data = (struct sound_display_data *) arg;

	(void)(app);

	RRR_MSG_0("Sound display window was closed\n");

	data->do_stop = 1;
}

static int text_refresh_word_push(struct rrr_nullsafe_str *output, struct sound_display_data *data, const char *word, int idx) {
	const int is_first = idx == 0;
	const int is_played = idx <= data->phrase_pos;

	static const int font_size = 1024 / 8 * 1000;
	static const char color_unplayed[] = "#ddd";
	static const char color_played[] = "#000";
	static const char open_format[] = "<span font_family=\"Sans\" font_weight=\"bold\" font_size=\"%i\" color=\"%s\">%s%s";
	static const char close[] = "</span>";


	if (rrr_nullsafe_str_append_asprintf (
			output,
			open_format,
			font_size,
			is_played ? color_played : color_unplayed,
			is_first ? "" : " ", word
	) != 0)
		return 1;

	if (rrr_nullsafe_str_append_raw(output, close, sizeof(close) - 1) != 0)
		return 1;

	return 0;
};

static gboolean text_refresh(gpointer arg) {
	struct sound_display_data *data = (struct sound_display_data *) arg;

	struct rrr_nullsafe_str *output = NULL;
	gboolean ret = TRUE;

	if (!data->text) {
		goto out;
	}

	if (rrr_nullsafe_str_new_or_replace_empty(&output) != 0) {
		ret = FALSE;
		goto out;
	}

	int i = 0;
	RRR_MAP_ITERATE_BEGIN(&data->phrase_full);
		if (text_refresh_word_push(output, data, node_tag, i++) != 0) {
			ret = FALSE;
			goto out_destroy_output;
		}
	RRR_MAP_ITERATE_END();

	char *output_final;

	if (rrr_nullsafe_str_extract_append_null(&output_final, output) != 0) {
		ret = FALSE;
		goto out_destroy_output;
	}

	gtk_label_set_markup(GTK_LABEL(data->text), output_final);

	rrr_free(output_final);

	out_destroy_output:
		rrr_nullsafe_str_destroy_if_not_null(&output);
	out:
		if (ret != TRUE)
			data->do_stop = 1;
		return ret;
}

int init_display(struct sound_display_data *data) {
	int ret = 0;

	GdkDisplay *display;

	if (data->window)
		goto out;

	if ((display = gdk_display_get_default()) == NULL) {
		RRR_MSG_1("Sound display could not get default display (yet)...");
		goto out;
	}

	RRR_MSG_1("Initializing sound display application...\n");

	g_signal_connect(display, "closed", G_CALLBACK(on_closed), data);

	g_timeout_add(200, text_refresh, data);

	if ((data->window = gtk_window_new(GTK_WINDOW_TOPLEVEL)) == NULL) {
		RRR_BUG("Failed to create sound display window\n");
	}

	g_signal_connect(data->window, "destroy", G_CALLBACK(on_destroy), data);

	gtk_window_set_title(GTK_WINDOW(data->window), "Sound Display");
	gtk_window_set_default_size(GTK_WINDOW(data->window), 1024, 768);

	data->grid = gtk_grid_new();
	data->hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
	data->text = gtk_label_new("");

#ifdef DEBUG_BOXES
	{
		GtkStyleContext *styleContext;
		GtkCssProvider *provider = gtk_css_provider_new();
		gtk_css_provider_load_from_data(provider,
			"#text { background-color: rgba(0, 255, 0, 0.2); }"
			"#hbox { background-color: rgba(255, 0, 0, 0.2); }"
			"#grid { background-color: rgba(0, 0, 255, 0.2); }",
			-1, NULL);
		styleContext = gtk_widget_get_style_context(data->hbox);
		gtk_style_context_add_provider(styleContext, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_USER);
		styleContext = gtk_widget_get_style_context(data->grid);
		gtk_style_context_add_provider(styleContext, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_USER);
		styleContext = gtk_widget_get_style_context(data->text);
		gtk_style_context_add_provider(styleContext, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_USER);
	}

	gtk_widget_set_name(data->text, "text");
	gtk_widget_set_name(data->hbox, "hbox");
	gtk_widget_set_name(data->grid, "grid");
#endif

	gtk_widget_set_valign(data->hbox, GTK_ALIGN_CENTER);
	gtk_widget_set_halign(data->hbox, GTK_ALIGN_CENTER);
	gtk_widget_set_vexpand(data->hbox, TRUE);
	gtk_widget_set_hexpand(data->hbox, TRUE);

	gtk_label_set_justify(GTK_LABEL(data->text), GTK_JUSTIFY_CENTER);
	gtk_label_set_line_wrap(GTK_LABEL(data->text), TRUE);
	gtk_widget_set_hexpand(data->text, TRUE);
	gtk_widget_set_halign(data->text, GTK_ALIGN_FILL);

	gtk_container_add(GTK_CONTAINER(data->hbox), data->text);
	gtk_container_add(GTK_CONTAINER(data->grid), data->hbox);
	gtk_container_add(GTK_CONTAINER(data->window), data->grid);

	gtk_window_fullscreen(GTK_WINDOW(data->window));

	gtk_widget_show_all(data->window);

	gloop();

	out:
		return ret;
}

int config(RRR_CONFIG_ARGS) {
	(void)(config);

	int ret = 0;

	struct sound_display_data *data;

	if (setenv("DISPLAY", ":0", 1) != 0) {
		RRR_MSG_0("Failed to set DISPLAY environment variable: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if (setenv("WAYLAND_DISPLAY", "wayland-0", 1) != 0) {
		RRR_MSG_0("Failed to set WAYLAND_DISPLAY environment variable: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if ((data = rrr_allocate_zero(sizeof(*data))) == NULL) {
		RRR_MSG_0("Failed to allocate data memory for sound display\n");
		ret = 1;
		goto out;
	}

	gtk_init(0, NULL);

	ctx->application_ptr = data;

	out:
	return ret;
}

void phrase_reset(struct sound_display_data *data) {
	rrr_map_clear(&data->phrase_full);
	data->phrase_pos = 0;
	data->phrase_expiration = rrr_time_get_64() + PHRASE_EXPIRATION_HARD_US;
}

int source(RRR_SOURCE_ARGS) {
	struct sound_display_data *data = ctx->application_ptr;

	(void)(message_addr);

	rrr_free(message);

	if (data->do_stop)
		return 1;

	if (rrr_time_get_64() >= data->phrase_expiration) {
		RRR_MSG_1("Reset phrase after timeout\n");
		phrase_reset(data);
	}

	if (data->window)
		gloop();

	return 0;
}

int phrase_full_word_cb(int idx, const char *str, void *arg) {
	struct sound_display_data *data = arg;

	int ret = 0;

	if (idx == 0) {
		RRR_MSG_1("Reset phrase\n");
		phrase_reset(data);
	}

	RRR_MSG_1("Adding unplayed word: %s\n", str);

	if ((ret = rrr_map_item_add_new(&data->phrase_full, str, NULL)) != 0)
		goto out;

	out:
	return ret;
}

int phrase_chunk_word_cb(int idx, const char *str, void *arg) {
	struct sound_display_data *data = arg;

	(void)(idx);

	int ret = 0;

	RRR_MSG_1("Marking word as played: %s\n", str);

	data->phrase_pos++;

	if (data->phrase_pos >= RRR_MAP_COUNT(&data->phrase_full))
		data->phrase_expiration = rrr_time_get_64() + PHRASE_EXPIRATION_SOFT_US;

	return ret;
}

int process(RRR_PROCESS_ARGS) {
	struct sound_display_data *data = ctx->application_ptr;

	(void)(message_addr);

	int ret = 0;

	uint16_t version_dummy;
	struct rrr_array array = {0};

	RRR_DBG_2("cmodule process timestamp %" PRIu64 " method %s\n",
		message->timestamp, method);

	if (!MSG_IS_ARRAY(message)) {
		RRR_MSG_0("Warning: Message to sound display process function was not an array message\n");
		goto out;
	}

	if (init_display(data) != 0 || data->do_stop) {
		ret = 1;
		goto out;
	}

	if (rrr_array_message_append_to_array(&version_dummy, &array, message) != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_array_get_values_str_by_tag(&array, "phrase_full_word", phrase_full_word_cb, data) != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_array_get_values_str_by_tag(&array, "phrase_chunk_word", phrase_chunk_word_cb, data) != 0) {
		ret = 1;
		goto out;
	}

	if (data->window)
		gloop();
	else
		RRR_MSG_1("Sound display app not yet initialized\n");

	out:
	rrr_array_clear(&array);
	rrr_free(message);
	return ret;
}

int cleanup(RRR_CLEANUP_ARGS) {
	struct sound_display_data *data = ctx->application_ptr;

	RRR_MSG_1("cmodule exiting\n");

	rrr_map_clear(&data->phrase_full);
	rrr_free(data);

	ctx->application_ptr = NULL;

	return 0;
}
