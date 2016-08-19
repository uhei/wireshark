/* packet-carp.c
 * Routines for Barracuda TINA VPN Protocol
 * Copyright 2013, Uli Heilmeier <uh@heilmeier.eu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>

static gint proto_tina = -1;
static gint ett_tina = -1;

static gint hf_tina_length = -1;
static gint hf_tina_type = -1;
static gint hf_tina_subtype = -1;
static gint hf_tina_data = -1;
static gint hf_tina_spi = -1;
static gint hf_tina_seq = -1;
static gint hf_tina_keep1 = -1;
static gint hf_tina_keep2 = -1;
static gint hf_tina_keep3 = -1;
static gint hf_tina_keep3a = -1;
static gint hf_tina_keep3b = -1;
static gint hf_tina_keep3c = -1;
static gint hf_tina_keep3d = -1;
static gint hf_tina_keep4 = -1;
static gint hf_tina_init1 = -1;
static gint hf_tina_localid = -1;
static gint hf_tina_init3 = -1;
static gint hf_tina_remoteid = -1;
static gint hf_tina_init5 = -1;
static gint hf_tina_init6 = -1;

static const value_string tina_message_types_vals[] = {
    { 0x01, "Init 1" },
    { 0x02, "Init 2" },
    { 0x03, "Init 3" },
    { 0x04, "Init 4" },
    { 0x05, "Init 5" },
    { 0x06, "Init 6" },
    { 0x11, "Enrypted Data" },
    { 0x13, "RekeyX Request" },
    { 0x14, "RekeyX Response" },
    { 0x15, "RekeyConfirm Request" },
    { 0x16, "RekeyConfirm Reply" },
    { 0x17, "Terminate" },
    { 0x21, "Keep-Alive Request" },
    { 0x22, "Keep-Alive Response" },
    { 0,  NULL },
};

static value_string_ext tina_message_type_short_str_vals_ext = VALUE_STRING_EXT_INIT(tina_message_types_vals);


/* This dissector works for TCP and UDP TINA packets */
#define TINA_PORT 691

static int
dissect_tina(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    gint16 tina_len;
    guint8 tina_type;
    proto_item *ti;
    proto_tree *tina_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TINA");
    col_clear(pinfo->cinfo, COL_INFO);


    ti = proto_tree_add_item(tree, proto_tina, tvb, 0, -1, ENC_NA);
    tina_tree = proto_item_add_subtree(ti, ett_tina);

    tina_len = tvb_get_ntohs(tvb, 0);
/*   proto_tree_add_item(tina_tree, hf_tina_length, tvb, offset, 2, ENC_BIG_ENDIAN); */
    proto_tree_add_uint_format(tina_tree, hf_tina_length, tvb, offset, 2, tina_len,
                               "TINA Length: %u bytes", tina_len);
    offset+=2;

    tina_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tina_tree, hf_tina_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(tina_type, &tina_message_type_short_str_vals_ext, "Unknown (%u)"));

    proto_tree_add_item(tina_tree, hf_tina_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if ( tina_type < 10 || tina_type == 19 || tina_type == 20 ) {
        proto_tree_add_item(tina_tree, hf_tina_init1, tvb, offset, 16, ENC_NA);
        offset+=16;
        proto_tree_add_item(tina_tree, hf_tina_init6, tvb, offset, 3, ENC_NA);
        offset+=3;
        proto_tree_add_item(tina_tree, hf_tina_init5, tvb, offset, 2, ENC_NA);
        offset+=2;
        proto_tree_add_item(tina_tree, hf_tina_remoteid, tvb, offset, 32, ENC_ASCII|ENC_NA);
        offset+=32;
        proto_tree_add_item(tina_tree, hf_tina_init3, tvb, offset, 1, ENC_NA);
        offset+=1;
        proto_tree_add_item(tina_tree, hf_tina_localid, tvb, offset, 32, ENC_ASCII|ENC_NA);
        offset+=32;
    }
    else if ( tina_type >= 10 ) {
        proto_tree_add_item(tina_tree, hf_tina_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        proto_tree_add_item(tina_tree, hf_tina_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        if ( tina_type == 33) {
            proto_tree_add_item(tina_tree, hf_tina_keep1, tvb, offset, 16, ENC_NA);
            offset+=16;
            proto_tree_add_item(tina_tree, hf_tina_keep2, tvb, offset, 32, ENC_NA);
            offset+=32;
            proto_tree_add_item(tina_tree, hf_tina_keep4, tvb, offset, 16, ENC_NA);
            offset+=16;
            proto_tree_add_item(tina_tree, hf_tina_keep3, tvb, offset, 12, ENC_NA);
            offset+=12;
            return offset;
        }
        else if ( tina_type == 34) {
            proto_tree_add_item(tina_tree, hf_tina_keep1, tvb, offset, 16, ENC_NA);
            offset+=16;
            proto_tree_add_item(tina_tree, hf_tina_keep2, tvb, offset, 32, ENC_NA);
            offset+=32;
            proto_tree_add_item(tina_tree, hf_tina_keep4, tvb, offset, 32, ENC_NA);
            offset+=32;
            proto_tree_add_item(tina_tree, hf_tina_keep3, tvb, offset, 12, ENC_NA);
            proto_tree_add_item(tina_tree, hf_tina_keep3a, tvb, offset, 3, ENC_NA);
            proto_tree_add_item(tina_tree, hf_tina_keep3b, tvb, offset+3, 2, ENC_NA);
            proto_tree_add_item(tina_tree, hf_tina_keep3c, tvb, offset+5, 6, ENC_NA);
            proto_tree_add_item(tina_tree, hf_tina_keep3d, tvb, offset+11, 1, ENC_NA);
            offset+=12;
            return offset;
        }
    }


    proto_tree_add_item(tina_tree, hf_tina_data, tvb, offset, -1, ENC_NA);

    return offset;
}

void proto_register_tina(void)
{
    static hf_register_info hf[] = {
        { &hf_tina_length,
          {"TINA Length", "tina.length",
           FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_type,
          {"TINA Type", "tina.type",
           FT_UINT8, BASE_HEX_DEC, VALS(tina_message_types_vals), 0x0,
           NULL, HFILL }},

        { &hf_tina_subtype,
          {"TINA Subtype", "tina.subtype",
           FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_data,
          {"TINA Data", "tina.data",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_spi,
          {"TINA SPI Number", "tina.spi",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_seq,
          {"TINA Sequence Number", "tina.seq",
           FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep1,
          {"TINA keep1", "tina.keep1",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep2,
          {"TINA keep2", "tina.keep2",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep4,
          {"TINA keep4", "tina.keep4",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep3,
          {"TINA keep3", "tina.keep3",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep3a,
          {"TINA keep3a", "tina.keep3a",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep3b,
          {"TINA keep3b", "tina.keep3b",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep3c,
          {"TINA keep3c", "tina.keep3c",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_keep3d,
          {"TINA keep3d", "tina.keep3d",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_init1,
          {"TINA init1", "tina.init1",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_localid,
          {"TINA Local ID", "tina.local_id",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_init3,
          {"TINA init3", "tina.init3",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_remoteid,
          {"TINA Remote ID", "tina.remote_id",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_init5,
          {"TINA init5", "tina.init5",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_tina_init6,
          {"TINA init6", "tina.init6",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_tina,
    };

    proto_tina = proto_register_protocol("Barracuda TINA VPN",
        "TINA", "tina");
    proto_register_field_array(proto_tina, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tina(void)
{
    dissector_handle_t tina_handle;

    tina_handle = create_dissector_handle(dissect_tina, proto_tina);
    dissector_add_uint("udp.port", TINA_PORT, tina_handle);
    dissector_add_uint("tcp.port", TINA_PORT, tina_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
