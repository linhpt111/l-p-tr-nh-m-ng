#include "utils.h"

typedef struct {
    GtkBuilder *builder;
    char *message;
    char *sender;
    gboolean is_sent;
} UiMsgPayload;

typedef struct {
    GtkBuilder *builder;
    clientDetails *clientD;
    char *csv;
} UiPresencePayload;

static gboolean idle_add_message_cb(gpointer data) {
    UiMsgPayload *p = (UiMsgPayload *)data;
    add_to_messages_interface(p->builder, p->message, p->is_sent, p->sender);
    g_object_unref(p->builder);
    free(p->message);
    free(p->sender);
    free(p);
    return FALSE;
}

static gboolean idle_refresh_presence_cb(gpointer data) {
    UiPresencePayload *p = (UiPresencePayload *)data;
    refresh_online_users(p->builder, p->clientD, p->csv);
    g_object_unref(p->builder);
    free(p->csv);
    free(p);
    return FALSE;
}

static gboolean idle_refresh_groups_cb(gpointer data) {
    UiPresencePayload *p = (UiPresencePayload *)data;
    refresh_groups(p->builder, p->clientD, p->csv);
    g_object_unref(p->builder);
    free(p->csv);
    free(p);
    return FALSE;
}

int setupClientFromGUI(clientDetails *clientD, GtkBuilder* builder) {
    clientD->clientSocketFD = get_socket();
    if (clientD->clientSocketFD == -1) {
        LOG_ERROR(" [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }

    GtkWidget* connection_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "connection_dialog"));
    GtkWidget* connection_dialog_button = GTK_WIDGET(gtk_builder_get_object(builder, "connection_dialog_button"));

    CDBHData *pack = (CDBHData *)malloc(sizeof(CDBHData));
    pack->data = clientD;
    pack->builder = builder;
    pack->connection_dialog = connection_dialog;

    g_signal_connect(connection_dialog_button, "clicked", G_CALLBACK(connection_dialog_button_handler), pack);

    gint response = gtk_dialog_run(GTK_DIALOG(connection_dialog));
    UNUSED(response);
    gtk_widget_hide(connection_dialog);

    return 0;
}

void connection_dialog_button_handler(GtkWidget* button, CDBHData *pack) {
    UNUSED(button);

    GtkWidget* ip_entry;
    GtkWidget* port_entry;
    GtkWidget* user_name_entry;

    ip_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "connection_dialog_ip_entry"));
    port_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "connection_dialog_port_entry"));
    user_name_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "connection_dialog_username_entry"));

    int port;

    const char* ip = gtk_entry_get_text(GTK_ENTRY(ip_entry));
    const char* port_str = gtk_entry_get_text(GTK_ENTRY(port_entry));
    const char* username = gtk_entry_get_text(GTK_ENTRY(user_name_entry));

    if (strlen(ip) < 1 || strlen(port_str) < 1 || strlen(username) < 1) {
        LOG_ERROR("All fields are required.");
        return;
    }

    char* endptr;
    errno = 0;

    port = (int)strtol(port_str, &endptr, 10);
    if (*endptr != '\0' && *endptr != '\n') {
        LOG_ERROR("Please input a correct PORT no. eg [ 2000 ]\n");
        return;
    }

    pack->data->serverAddress = get_address(&port, ip);
    pack->data->clientName = get_client_name(username);
    memset(pack->data->active_target, 0, sizeof(pack->data->active_target));
    pack->data->active_target_is_group = FALSE;

    if (connect(pack->data->clientSocketFD, pack->data->serverAddress, sizeof(*(pack->data->serverAddress))) < 0) {
        LOG_ERROR("Failed to connect to server: %s", strerror(errno));
    } else {
        LOG_SUCCESS("Successfully connected to the server.");
        pack->connection_status = TRUE;
    }

    gtk_dialog_response(GTK_DIALOG(pack->connection_dialog), GTK_RESPONSE_OK);
}

void *sendMessagesWithGUI(void *pack_ptr) {
    SMData *pack = (SMData *)pack_ptr;

    GtkWidget* send_button = GTK_WIDGET(gtk_builder_get_object(pack->builder, "send_button"));
    GtkWidget* group_button = GTK_WIDGET(gtk_builder_get_object(pack->builder, "group_create_button"));
    GtkWidget* group_join_button = GTK_WIDGET(gtk_builder_get_object(pack->builder, "group_join_button"));
    GtkWidget* group_list = GTK_WIDGET(gtk_builder_get_object(pack->builder, "group_list"));

    SMHPack *smh_pack = malloc(sizeof(SMHPack));
    smh_pack->data = pack->data;
    smh_pack->builder = pack->builder;

    g_signal_connect(send_button, "clicked", G_CALLBACK(send_message_handler), smh_pack);
    if (group_button) {
        g_signal_connect(group_button, "clicked", G_CALLBACK(on_group_create), pack);
    }
    if (group_join_button) {
        g_signal_connect(group_join_button, "clicked", G_CALLBACK(on_group_join), pack);
    }
    if (group_list) {
        g_signal_connect(group_list, "row-selected", G_CALLBACK(on_group_selected), pack);
    }

    return NULL;
}

void send_message_handler(GtkWidget *button, SMHPack* pack) {
    UNUSED(button);

    GtkWidget* message_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "message_entry"));

    const char* message = gtk_entry_get_text(GTK_ENTRY(message_entry));

    if (strlen(message) >= 1) {
        const char *target = NULL;
        if (strlen(pack->data->active_target) > 0) {
            target = pack->data->active_target;
        }

        char header[CLIENT_NAME_INPUT_MAX * 2];
        if (target) {
            if (pack->data->active_target_is_group) {
                if (!pack->data->group_joined) {
                    LOG_ERROR("Please join the group before sending messages.");
                    gtk_entry_set_text(GTK_ENTRY(message_entry), "");
                    return;
                }
                snprintf(header, sizeof(header), "You -> #%s", target);
            } else {
                snprintf(header, sizeof(header), "You -> %s", target);
            }
        } else {
            snprintf(header, sizeof(header), "You");
        }
        add_to_messages_interface(pack->builder, message, TRUE, header);
        unsigned char iv[16];

        RAND_bytes(iv, sizeof(iv));

        char payload[NETWORK_MESSAGE_BUFFER_SIZE];
        if (target) {
            if (pack->data->active_target_is_group) {
                snprintf(payload, sizeof(payload), "MSG|GROUP:%s|%s|%s", target, pack->data->clientName, message);
            } else {
                snprintf(payload, sizeof(payload), "MSG|DM:%s|%s|%s", target, pack->data->clientName, message);
            }
        } else {
            snprintf(payload, sizeof(payload), "MSG|ALL|%s|%s", pack->data->clientName, message);
        }

        char* ciphertext = encrypt_with_aes(payload, pack->data->aes_key, iv);

        size_t packet_len = sizeof(iv) + strlen(ciphertext);
        unsigned char* packet = malloc(packet_len);

        memcpy(packet, iv, sizeof(iv));
        memcpy(packet + sizeof(iv), ciphertext, strlen(ciphertext));

        if (send(pack->data->clientSocketFD, packet, packet_len, 0) == -1) {
            pack->status = FALSE;
            LOG_ERROR("Send failed");
        } else {
            pack->status = TRUE;
        }
    }
    gtk_entry_set_text(GTK_ENTRY(message_entry), "");
}

void add_to_messages_interface(GtkBuilder* builder, const char* message, gboolean is_sent, const char* sender_username) {
    GtkWidget* messages_interface = GTK_WIDGET(gtk_builder_get_object(builder, "messages_interface"));
    if (!messages_interface || !GTK_IS_LIST_BOX(messages_interface)) {
        g_error("Invalid messages_interface!");
        return;
    }

    GtkWidget* row = gtk_list_box_row_new();
    if (!row) {
        g_error("Failed to create GtkListBoxRow!");
        return;
    }

    GtkWidget* message_node = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    if (!message_node) {
        g_error("Failed to create message_node!");
        return;
    }

    GtkWidget* message_label = gtk_label_new(message);
    GtkWidget* username_label = gtk_label_new(sender_username);

    if (!message_label || !username_label) {
        g_error("Failed to create labels!");
        return;
    }

    gtk_widget_set_halign(message_label, GTK_ALIGN_START);
    gtk_widget_set_halign(username_label, GTK_ALIGN_END);

    gtk_box_pack_start(GTK_BOX(message_node), message_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(message_node), username_label, FALSE, FALSE, 0);

    if (is_sent) {
        gtk_widget_set_halign(message_node, GTK_ALIGN_END);
        gtk_widget_set_margin_start(message_node, 50);
    } else {
        gtk_widget_set_halign(message_node, GTK_ALIGN_START);
        gtk_widget_set_margin_end(message_node, 50);
    }

    gtk_container_add(GTK_CONTAINER(row), message_node);
    gtk_list_box_insert(GTK_LIST_BOX(messages_interface), row, -1);

    g_print("About to show all widgets...\n");

    if (GTK_IS_WIDGET(row)) {
        gtk_widget_show_all(row);
    } else {
        g_error("row is invalid before gtk_widget_show_all!");
    }
}

void *receiveMessagesWithGUI(void *pack) {
    clientDetails *clientD = ((RMWGUI *)pack)->clientD;
    GtkBuilder* builder = ((RMWGUI *)pack)->builder;
    char buffer[NETWORK_MESSAGE_BUFFER_SIZE];
    ssize_t bytesReceived;

    clientD->public_key = NULL;
    clientD->group_joined = FALSE;

    unsigned char static_aes_key[32] = {
            0xC9, 0xED, 0x07, 0xED, 0x15, 0x98, 0x0C, 0x3D,
            0x27, 0xC9, 0x84, 0xEC, 0x11, 0x67, 0xA2, 0xAC,
            0xC8, 0x0A, 0x30, 0xC2, 0xD9, 0xB1, 0x1F, 0xC1,
            0x94, 0x4E, 0xC2, 0xB8, 0xB2, 0xC5, 0x58, 0x2E
        };

    while (1) {
        bytesReceived = recv(clientD->clientSocketFD, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived < 0) {
            LOG_ERROR("Receive failed");
            break;
        } else if (bytesReceived == 0) {
            LOG_INFO("Server disconnected.\n");
            break;
        }

        buffer[bytesReceived] = '\0';

        if (clientD->public_key) {
            if (bytesReceived < 16) {
                LOG_ERROR("Received data is too small for IV extraction.");
                break;
            }

            unsigned char iv[16];
            memcpy(iv, buffer, 16);

            char message[NETWORK_MESSAGE_BUFFER_SIZE];
            size_t message_length = bytesReceived - 16;
            memcpy(message, buffer + 16, message_length);
            message[message_length] = '\0';

            char *decrypted_message = decrypt_with_aes(message, static_aes_key, iv);
            if (!decrypted_message) {
                continue;
            }

            char *saveptr = NULL;
            char *type = strtok_r(decrypted_message, "|", &saveptr);
            if (type && strcmp(type, "PRESENCE") == 0) {
                char *csv = strtok_r(NULL, "|", &saveptr);
                UiPresencePayload *p = malloc(sizeof(UiPresencePayload));
                p->builder = g_object_ref(builder);
                p->clientD = clientD;
                p->csv = csv ? g_strdup(csv) : g_strdup("");
                g_idle_add(idle_refresh_presence_cb, p);
                free(decrypted_message);
                continue;
            } else if (type && strcmp(type, "GROUPS") == 0) {
                char *csv = strtok_r(NULL, "|", &saveptr);
                UiPresencePayload *p = malloc(sizeof(UiPresencePayload));
                p->builder = g_object_ref(builder);
                p->clientD = clientD;
                p->csv = csv ? g_strdup(csv) : g_strdup("");
                g_idle_add(idle_refresh_groups_cb, p);
                free(decrypted_message);
                continue;
            }

            if (type && strcmp(type, "MSG") == 0) {
                char *channel = strtok_r(NULL, "|", &saveptr);
                char *sender = strtok_r(NULL, "|", &saveptr);
                char *body = strtok_r(NULL, "", &saveptr);

                gboolean is_sent = sender && clientD->clientName && strcmp(sender, clientD->clientName) == 0;
                char header[CLIENT_NAME_INPUT_MAX * 2];

                if (channel && strncmp(channel, MESSAGE_TYPE_DM_PREFIX, strlen(MESSAGE_TYPE_DM_PREFIX)) == 0) {
                    const char *target = channel + strlen(MESSAGE_TYPE_DM_PREFIX);
                    if (is_sent) {
                        snprintf(header, sizeof(header), "You -> %s", target);
                    } else {
                        snprintf(header, sizeof(header), "%s -> you", sender ? sender : "Unknown");
                    }
                } else if (channel && strncmp(channel, MESSAGE_TYPE_GROUP_PREFIX, strlen(MESSAGE_TYPE_GROUP_PREFIX)) == 0) {
                    const char *group = channel + strlen(MESSAGE_TYPE_GROUP_PREFIX);
                    if (is_sent) {
                        snprintf(header, sizeof(header), "[#%s] You", group);
                    } else {
                        snprintf(header, sizeof(header), "[#%s] %s", group, sender ? sender : "Unknown");
                    }
                } else {
                    snprintf(header, sizeof(header), "%s", sender ? sender : "Unknown");
                }

                UiMsgPayload *p = malloc(sizeof(UiMsgPayload));
                p->builder = g_object_ref(builder);
                p->message = g_strdup(body ? body : "");
                p->sender = g_strdup(header);
                p->is_sent = is_sent;
                g_idle_add(idle_add_message_cb, p);
            }

            free(decrypted_message);
        } else {
            g_print("Public key trying to sync\n");
            process_public_key(buffer, &clientD->public_key);
            if (clientD->public_key) {
                g_print("Public Key synced...\n");

                unsigned char *aes_key = generate_aes_key(AES_KEY_SIZE);

                clientD->aes_key = aes_key;
                unsigned char encrypted_aes_key[RSA_size(clientD->public_key)];
                int encrypted_key_len = RSA_public_encrypt(
                    AES_KEY_SIZE,
                    aes_key,
                    encrypted_aes_key,
                    clientD->public_key,
                    RSA_PKCS1_OAEP_PADDING
                );

                if (encrypted_key_len == -1) {
                    fprintf(stderr, "Error encrypting AES key: %s\n", ERR_error_string(ERR_get_error(), NULL));
                    exit(EXIT_FAILURE);
                }

                char *b64_encoded_key = bytes_to_base64_encode(encrypted_aes_key, encrypted_key_len);

                if (send(clientD->clientSocketFD, b64_encoded_key, strlen(b64_encoded_key), 0) == -1) {
                    LOG_ERROR("Sending AES_key failed");
                    free(b64_encoded_key);
                    exit(EXIT_FAILURE);
                }
                free(b64_encoded_key);

                bytesReceived = recv(clientD->clientSocketFD, buffer, sizeof(buffer) - 1, 0);
                if (bytesReceived < 0) {
                    LOG_ERROR("Receive failed");
                    break;
                } else if (bytesReceived == 0) {
                    LOG_INFO("Server disconnected.\n");
                    break;
                }

                buffer[bytesReceived] = '\0';
            }

            size_t name_len = strlen(clientD->clientName) + 1;
            if (send(clientD->clientSocketFD, clientD->clientName, name_len, 0) < 0) {
                LOG_ERROR("Failed to send user details to server: %s", strerror(errno));
                close(clientD->clientSocketFD);
                free(clientD->clientName);
                free(clientD->serverAddress);
                return NULL;
            }
            LOG_SUCCESS("Successfully sent client details to the server.");
        }
    }

    return NULL;
}

void refresh_online_users(GtkBuilder* builder, clientDetails *clientD, const char* csv_users) {
    GtkWidget* list = GTK_WIDGET(gtk_builder_get_object(builder, "online_user_list"));
    if (!list || !GTK_IS_LIST_BOX(list)) return;

    GList *rows = gtk_container_get_children(GTK_CONTAINER(list));
    for (GList *iter = rows; iter != NULL; iter = iter->next) {
        gtk_widget_destroy(GTK_WIDGET(iter->data));
    }
    g_list_free(rows);

    GtkWidget* all_row = gtk_list_box_row_new();
    GtkWidget* all_label = gtk_label_new("Everyone");
    gtk_container_add(GTK_CONTAINER(all_row), all_label);
    gtk_list_box_insert(GTK_LIST_BOX(list), all_row, -1);

    if (csv_users && strlen(csv_users) > 0) {
        char *copy = g_strdup(csv_users);
        char *saveptr = NULL;
        char *token = strtok_r(copy, ",", &saveptr);
        while (token) {
            if (clientD->clientName && strcmp(token, clientD->clientName) != 0) {
                GtkWidget* row = gtk_list_box_row_new();
                GtkWidget* label = gtk_label_new(token);
                gtk_container_add(GTK_CONTAINER(row), label);
                gtk_list_box_insert(GTK_LIST_BOX(list), row, -1);
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        g_free(copy);
    }

    gtk_widget_show_all(list);

    GList *children = gtk_container_get_children(GTK_CONTAINER(list));
    GtkListBoxRow *selected = NULL;
    for (GList *iter = children; iter != NULL; iter = iter->next) {
        GtkWidget *row = GTK_WIDGET(iter->data);
        GtkWidget *child = gtk_bin_get_child(GTK_BIN(row));
        const char *label_text = gtk_label_get_text(GTK_LABEL(child));
        if (strlen(clientD->active_target) == 0 && strcmp(label_text, "Everyone") == 0) {
            selected = GTK_LIST_BOX_ROW(row);
            break;
        }
        if (strlen(clientD->active_target) > 0 && strcmp(label_text, clientD->active_target) == 0) {
            selected = GTK_LIST_BOX_ROW(row);
            break;
        }
    }
    if (selected) {
        gtk_list_box_select_row(GTK_LIST_BOX(list), selected);
    }
    g_list_free(children);
}

void on_online_user_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    UNUSED(box);
    SMData *ctx = (SMData *)user_data;
    if (!row || !ctx || !ctx->data) return;

    clientDetails *clientD = ctx->data;
    GtkBuilder *builder = ctx->builder;

    GtkWidget *child = gtk_bin_get_child(GTK_BIN(row));
    const char *label_text = gtk_label_get_text(GTK_LABEL(child));
    if (strcmp(label_text, "Everyone") == 0) {
        clientD->active_target[0] = '\0';
        clientD->active_target_is_group = FALSE;
    } else {
        strncpy(clientD->active_target, label_text, sizeof(clientD->active_target) - 1);
        clientD->active_target[sizeof(clientD->active_target) - 1] = '\0';
        clientD->active_target_is_group = FALSE;
    }

    GtkWidget *header_label = GTK_WIDGET(gtk_builder_get_object(builder, "chat_header_label"));
    GtkWidget *subtitle_label = GTK_WIDGET(gtk_builder_get_object(builder, "chat_subtitle_label"));

    if (header_label) {
        if (strlen(clientD->active_target) == 0) {
            gtk_label_set_text(GTK_LABEL(header_label), "Group chat");
        } else {
            gtk_label_set_text(GTK_LABEL(header_label), clientD->active_target);
        }
    }
    if (subtitle_label) {
        if (strlen(clientD->active_target) == 0) {
            gtk_label_set_text(GTK_LABEL(subtitle_label), "Broadcasting to everyone");
        } else {
            gtk_label_set_text(GTK_LABEL(subtitle_label), "Direct message");
        }
    }
}

void refresh_groups(GtkBuilder* builder, clientDetails *clientD, const char* csv_groups) {
    GtkWidget* list = GTK_WIDGET(gtk_builder_get_object(builder, "group_list"));
    if (!list || !GTK_IS_LIST_BOX(list)) return;

    GList *rows = gtk_container_get_children(GTK_CONTAINER(list));
    for (GList *iter = rows; iter != NULL; iter = iter->next) {
        gtk_widget_destroy(GTK_WIDGET(iter->data));
    }
    g_list_free(rows);

    if (csv_groups && strlen(csv_groups) > 0) {
        char *copy = g_strdup(csv_groups);
        char *saveptr = NULL;
        char *token = strtok_r(copy, ",", &saveptr);
        while (token) {
            GtkWidget* row = gtk_list_box_row_new();
            GtkWidget* label = gtk_label_new(token);
            gtk_container_add(GTK_CONTAINER(row), label);
            gtk_list_box_insert(GTK_LIST_BOX(list), row, -1);
            token = strtok_r(NULL, ",", &saveptr);
        }
        g_free(copy);
    }

    gtk_widget_show_all(list);
}

void on_group_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    UNUSED(box);
    SMData *ctx = (SMData *)user_data;
    if (!row || !ctx || !ctx->data) return;

    clientDetails *clientD = ctx->data;
    GtkBuilder *builder = ctx->builder;

    GtkWidget *child = gtk_bin_get_child(GTK_BIN(row));
    const char *label_text = gtk_label_get_text(GTK_LABEL(child));
    strncpy(clientD->active_target, label_text, sizeof(clientD->active_target) - 1);
    clientD->active_target[sizeof(clientD->active_target) - 1] = '\0';
    clientD->active_target_is_group = TRUE;
    clientD->group_joined = FALSE;

    GtkWidget *header_label = GTK_WIDGET(gtk_builder_get_object(builder, "chat_header_label"));
    GtkWidget *subtitle_label = GTK_WIDGET(gtk_builder_get_object(builder, "chat_subtitle_label"));

    if (header_label) {
        gtk_label_set_text(GTK_LABEL(header_label), clientD->active_target);
    }
    if (subtitle_label) {
        gtk_label_set_text(GTK_LABEL(subtitle_label), "Group selected (not joined)");
    }
}

void on_group_create(GtkButton *button, gpointer user_data) {
    UNUSED(button);
    SMData *ctx = (SMData *)user_data;
    if (!ctx || !ctx->data) return;

    GtkBuilder *builder = ctx->builder;
    clientDetails *clientD = ctx->data;

    GtkWidget *entry = GTK_WIDGET(gtk_builder_get_object(builder, "group_entry"));
    const char *name = gtk_entry_get_text(GTK_ENTRY(entry));
    if (!name || strlen(name) == 0) return;

    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    char payload[NETWORK_MESSAGE_BUFFER_SIZE];
    snprintf(payload, sizeof(payload), "GROUP|CREATE|%s", name);
    char *ciphertext = encrypt_with_aes(payload, clientD->aes_key, iv);
    if (ciphertext) {
        size_t packet_len = sizeof(iv) + strlen(ciphertext);
        unsigned char* packet = malloc(packet_len);
        memcpy(packet, iv, sizeof(iv));
        memcpy(packet + sizeof(iv), ciphertext, strlen(ciphertext));
        send(clientD->clientSocketFD, packet, packet_len, 0);
        free(packet);
        free(ciphertext);
    }
    gtk_entry_set_text(GTK_ENTRY(entry), "");
}

void on_group_join(GtkButton *button, gpointer user_data) {
    UNUSED(button);
    SMData *ctx = (SMData *)user_data;
    if (!ctx || !ctx->data) return;
    clientDetails *clientD = ctx->data;
    GtkBuilder *builder = ctx->builder;

    if (strlen(clientD->active_target) == 0 || !clientD->active_target_is_group) {
        LOG_ERROR("Select a group before joining.");
        return;
    }

    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    char payload[NETWORK_MESSAGE_BUFFER_SIZE];
    snprintf(payload, sizeof(payload), "GROUP|JOIN|%s", clientD->active_target);
    char *ciphertext = encrypt_with_aes(payload, clientD->aes_key, iv);
    if (ciphertext) {
        size_t packet_len = sizeof(iv) + strlen(ciphertext);
        unsigned char* packet = malloc(packet_len);
        memcpy(packet, iv, sizeof(iv));
        memcpy(packet + sizeof(iv), ciphertext, strlen(ciphertext));
        send(clientD->clientSocketFD, packet, packet_len, 0);
        free(packet);
        free(ciphertext);
    }

    clientD->group_joined = TRUE;
    GtkWidget *header_label = GTK_WIDGET(gtk_builder_get_object(builder, "chat_header_label"));
    GtkWidget *subtitle_label = GTK_WIDGET(gtk_builder_get_object(builder, "chat_subtitle_label"));
    if (header_label) {
        gtk_label_set_text(GTK_LABEL(header_label), clientD->active_target);
    }
    if (subtitle_label) {
        gtk_label_set_text(GTK_LABEL(subtitle_label), "Group chat");
    }
}
