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
#include "../lib/rrr_types.h"

// #define DEBUG_BOXES

struct sound_display_data {
	GtkWidget *window;
	GtkWidget *hbox;
	GtkWidget *grid;
	GtkWidget *text;
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

struct text_refresh_split_callback_data {
	struct rrr_nullsafe_str *output;
};

static int text_refresh_split_callback(const struct rrr_nullsafe_str *phrase, int is_last, void *arg) {
	struct text_refresh_split_callback_data *callback_data = arg;
	struct rrr_nullsafe_str *output = callback_data->output;

	char *str = ((void **)phrase)[0];

	printf("str: %s len: %lu\n", str, rrr_nullsafe_str_len(phrase));

	(void)(is_last);

	static const int font_size = 1024 / 8 * 1000;
	static const char color[] = "#333";
	static const char open_format[] = "<span font_family=\"Sans\" font_weight=\"bold\" font_size=\"%i\" color=\"%s\">%s";
	static const char close[] = "</span>";

	const int is_first = rrr_nullsafe_str_len(output) == 0;

	if (rrr_nullsafe_str_len(phrase) == 0)
		return 0;

	if (rrr_nullsafe_str_append_asprintf(output, open_format, font_size, color, is_first ? "" : " ") != 0)
		return 1;

	if (rrr_nullsafe_str_append(output, phrase) != 0)
		return 1;

	if (rrr_nullsafe_str_append_raw(output, close, sizeof(close) - 1) != 0)
		return 1;

	printf("len now: %lu\n", rrr_nullsafe_str_len(output));

	return 0;
};

static gboolean text_refresh(gpointer arg) {
	struct sound_display_data *data = (struct sound_display_data *) arg;

	struct rrr_nullsafe_str *output = NULL;
	struct rrr_nullsafe_str *input = NULL;
	gboolean ret = TRUE;

	if (!data->text) {
		goto out;
	}

	if (rrr_nullsafe_str_new_or_replace_empty(&output) != 0) {
		ret = FALSE;
		goto out;
	}

	static const char phrase[] = "THIS IS A VERY LONG PHRASE TAKING UP MULTIPLE LINES";

	if (rrr_nullsafe_str_new_or_append_raw(&input, phrase, sizeof(phrase) - 1) != 0) {
		ret = FALSE;
		goto out_destroy_output;
	}

	struct text_refresh_split_callback_data callback_data = {
		output
	};

	if (rrr_nullsafe_str_split(input, ' ', text_refresh_split_callback, &callback_data) != 0) {
		ret = FALSE;
		goto out_destroy_input;
	}

	char *output_final;

	if (rrr_nullsafe_str_extract_append_null(&output_final, output) != 0) {
		ret = FALSE;
		goto out_destroy_input;
	}

	printf("output: %s len: %lu\n", output_final, rrr_nullsafe_str_len(output));

	gtk_label_set_markup(GTK_LABEL(data->text), output_final);

	rrr_free(output_final);

	out_destroy_input:
		rrr_nullsafe_str_destroy_if_not_null(&input);
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

int source(RRR_SOURCE_ARGS) {
	struct sound_display_data *data = ctx->application_ptr;

	(void)(message_addr);

	rrr_free(message);

	if (data->do_stop)
		return 1;

	if (data->window)
		gloop();

	return 0;
}

int process(RRR_PROCESS_ARGS) {
	struct sound_display_data *data = ctx->application_ptr;

	RRR_DBG_2("cmodule process timestamp %" PRIu64 " method %s\n",
		message->timestamp, method);

	if (init_display(data) != 0 || data->do_stop) {
		rrr_free(message);
		return 1;
	}

	if (data->window)
		gloop();
	else
		RRR_MSG_1("Sound display app not yet initialized\n");

	return rrr_send_and_free(ctx, message, message_addr);
}

int cleanup(RRR_CLEANUP_ARGS) {
	struct sound_display_data *data = ctx->application_ptr;

	RRR_MSG_1("cmodule exiting\n");

	rrr_free(data);

	ctx->application_ptr = NULL;

	return 0;
}
