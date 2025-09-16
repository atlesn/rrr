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

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "cmodule.h"
#include "../lib/rrr_strerror.h"

#define DEBUG_BOXES

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

static gboolean text_refresh(gpointer arg) {
	struct sound_display_data *data = (struct sound_display_data *) arg;

	if (!data->text)
		return TRUE;

	int font_size = 1024 / 8 * 1000;

	const char *str = "THIS IS A VERY LONG STRING WITH MANY WORD WHICH MAY WRAP";
	const char *format ="<span font_family=\"Sans\" font_weight=\"bold\" font_size=\"%i\">%s</span>";
	size_t size = 12 + strlen(str) + strlen(format) + 1;

	char *tmp = rrr_allocate(size);

	sprintf(tmp, "<span font_family=\"Sans\" font_weight=\"bold\" font_size=\"%i\">%s</span>", font_size, str);
	tmp[size - 1] = '\0';
	gtk_label_set_markup(GTK_LABEL(data->text), tmp);

	rrr_free(tmp);

	return TRUE;
}

int init_display(struct sound_display_data *data) {
	int ret = 0;

	if (data->window)
		goto out;

	GdkDisplay *display = gdk_display_get_default();
	if (!display) {
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

	gtk_init(0, NULL);

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
