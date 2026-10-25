/* kind=block — «Блок»: трафик правила не пропускается (решение владельца 2026-10-13, переключатель
 * правила «Туннель | Блок | Напрямую» в splify2).
 *
 * АДРЕСА. Выходу метка и метка соединения — как у любого выхода; устройства, таблицы и помощника нет.
 * Пакет с меткой блока уходит обычным маршрутом, и цепочки filter на хуках forward (клиенты) и output
 * (сам роутер) его отвергают: TCP — сбросом (RST), чтобы приложение не висело до своего срока, всё
 * остальное — ICMP «запрещено» (admin-prohibited): UDP-приложение (QUIC, игры) узнаёт об отказе
 * сразу, а не через таймаут. Отвергается по метке СОЕДИНЕНИЯ, как у очереди модуля DPI: метку
 * пакета между prerouting и forward переписывают чужие (Tailscale), метку соединения — никто.
 *
 * ДОМЕНЫ. Доменное правило в блок не кладёт адресов в наборы: настоящий адрес часто общий у CDN, и
 * блок по нему закрыл бы всё, что за ним (решение владельца). Резолвер на имена такого правила
 * отвечает сам — A 0.0.0.0 и AAAA :: (канал с признаком block, tabfmt.h), не спрашивая апстрим;
 * соединение к 0.0.0.0 падает сразу, без повторных запросов. Режим resolve у такого правила не
 * значит ничего. */
#include <stdio.h>
#include "spec.h"
#include "ir.h"

static void block_chain(struct nft_table *t, const char *name, const char *hook) {
    struct nft_chain *c = ir_base_chain_add(t, name, "filter", hook, "filter", -5);
    ir_gap(c);
}

static void block_emit(struct nft_rs *rs, const struct spec *sp, const struct output *o) {
    (void)sp;
    struct nft_table *t = ir_table_find(rs, NFT_FAM_INET, NULL);
    if (!ir_chain_find(t, "forward_block")) {
        block_chain(t, "forward_block", "forward");
        block_chain(t, "output_block", "output");
    }
    static const char *const chains[2] = { "forward_block", "output_block" };
    for (int k = 0; k < 2; k++) {
        struct nft_chain *c = ir_chain_find(t, chains[k]);
        struct nft_rule *r = ir_rule(c);
        /* Только исходное направление: ответ отказа (RST, ICMP) привязан к тому же соединению и
         * несёт ту же метку — без условия output_block отбрасывал бы уже его, и клиент ждал бы
         * своего срока вместо мгновенного отказа (стенд QEMU 2026-10-13). */
        ir_x(r, "ct direction original");
        ir_x(r, "ct mark and 0x%08x == 0x%08x", STEER_MARK_MASK, o->mark);
        ir_x(r, "meta l4proto tcp");
        ir_counter(r, 0, 0);
        ir_x(r, "reject with tcp reset");
        ir_comment(r, "steer:block:%s", o->name);
        r = ir_rule(c);
        ir_x(r, "ct direction original");
        ir_x(r, "ct mark and 0x%08x == 0x%08x", STEER_MARK_MASK, o->mark);
        ir_counter(r, 0, 0);
        ir_x(r, "reject with icmpx admin-prohibited");
        ir_comment(r, "steer:block:%s", o->name);
    }
}

const struct kind_ops kind_block = {
    .name = "block",
    .caps = KC_MARK | KC_CTMARK | KC_SKIP_ZAPRET | KC_IPV6,
    .emit = block_emit,
};

int out_is_block(const struct output *o) { return o && kind_of(o) == &kind_block; }
