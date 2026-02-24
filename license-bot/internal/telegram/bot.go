package telegram

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"kypaqet-license-bot/internal/store"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type Bot struct {
	api         *tgbotapi.BotAPI
	adminChatID int64
	st          store.Store

	mu     sync.Mutex
	states map[int64]pendingState
}

type pendingState string

const (
	stateNone        pendingState = ""
	stateNewLicense  pendingState = "new_license"
	stateAskInfo     pendingState = "ask_info"
	stateAskSetLimit pendingState = "ask_setlimit"
	stateAskEnable   pendingState = "ask_enable"
	stateAskDisable  pendingState = "ask_disable"
)

func NewBot(token string, adminChatID int64, st store.Store) (*Bot, error) {
	api, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		return nil, err
	}
	api.Debug = false
	return &Bot{api: api, adminChatID: adminChatID, st: st, states: map[int64]pendingState{}}, nil
}

func (b *Bot) Run(ctx context.Context) error {
	upd := tgbotapi.NewUpdate(0)
	upd.Timeout = 30
	updates := b.api.GetUpdatesChan(upd)

	for {
		select {
		case <-ctx.Done():
			return nil
		case u := <-updates:
			if u.CallbackQuery != nil {
				b.handleCallback(u.CallbackQuery)
				continue
			}
			if u.Message != nil {
				b.handleMessage(u.Message)
				continue
			}
		}
	}
}

func (b *Bot) handleMessage(m *tgbotapi.Message) {
	chatID := m.Chat.ID
	text := strings.TrimSpace(m.Text)
	if text == "" {
		return
	}

	// Only admin can manage
	if chatID != b.adminChatID {
		msg := tgbotapi.NewMessage(chatID, "این ربات فقط برای ادمین فعال است.")
		_, _ = b.api.Send(msg)
		return
	}

	// Allow /start and /help but the UX is button-first.
	if strings.HasPrefix(text, "/start") || strings.HasPrefix(text, "/help") || strings.HasPrefix(text, "/menu") {
		b.sendMenu(chatID, "منوی مدیریت لایسنس")
		b.setState(chatID, stateNone)
		return
	}

	st := b.getState(chatID)
	switch st {
	case stateNewLicense:
		b.handleNewLicenseInput(chatID, text)
		return
	case stateAskInfo:
		b.setState(chatID, stateNone)
		b.cmdInfo(chatID, []string{text})
		b.sendMenu(chatID, "")
		return
	case stateAskSetLimit:
		b.handleSetLimitInput(chatID, text)
		return
	case stateAskEnable:
		b.setState(chatID, stateNone)
		b.cmdEnable(chatID, []string{text}, true)
		b.sendMenu(chatID, "")
		return
	case stateAskDisable:
		b.setState(chatID, stateNone)
		b.cmdEnable(chatID, []string{text}, false)
		b.sendMenu(chatID, "")
		return
	default:
		b.sendMenu(chatID, "برای مدیریت از دکمه‌ها استفاده کن.")
		return
	}
}

func (b *Bot) handleCallback(q *tgbotapi.CallbackQuery) {
	chatID := q.Message.Chat.ID

	// Only admin can manage
	if chatID != b.adminChatID {
		_ = b.answerCallback(q.ID, "اجازه دسترسی ندارید")
		return
	}

	data := strings.TrimSpace(q.Data)
	_ = b.answerCallback(q.ID, "")

	switch {
	case data == "menu":
		b.setState(chatID, stateNone)
		b.sendMenu(chatID, "منوی مدیریت")
	case data == "new":
		b.setState(chatID, stateNewLicense)
		b.reply(chatID, "عدد limit را بفرست (اختیاری: بعدش note)\nمثال: 3 مشتری-الف")
	case data == "list":
		b.setState(chatID, stateNone)
		b.cmdListWithButtons(chatID)
	case data == "ask_info":
		b.setState(chatID, stateAskInfo)
		b.reply(chatID, "کلید لایسنس را ارسال کن:")
	case data == "ask_setlimit":
		b.setState(chatID, stateAskSetLimit)
		b.reply(chatID, "فرمت: <license> <limit>\nمثال: KYPAQET-.... 5")
	case data == "ask_enable":
		b.setState(chatID, stateAskEnable)
		b.reply(chatID, "کلید لایسنس را ارسال کن تا فعال شود:")
	case data == "ask_disable":
		b.setState(chatID, stateAskDisable)
		b.reply(chatID, "کلید لایسنس را ارسال کن تا غیرفعال شود:")
	case strings.HasPrefix(data, "info:"):
		b.setState(chatID, stateNone)
		key := strings.TrimPrefix(data, "info:")
		b.cmdInfo(chatID, []string{key})
		b.sendMenu(chatID, "")
	default:
		b.sendMenu(chatID, "عملیات نامعتبر")
	}
}

func (b *Bot) sendMenu(chatID int64, title string) {
	if strings.TrimSpace(title) == "" {
		title = "منو"
	}
	msg := tgbotapi.NewMessage(chatID, title)
	msg.DisableWebPagePreview = true
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("➕ ساخت لایسنس", "new"),
			tgbotapi.NewInlineKeyboardButtonData("📋 لیست", "list"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("ℹ️ اطلاعات", "ask_info"),
			tgbotapi.NewInlineKeyboardButtonData("✏️ تغییر لیمیت", "ask_setlimit"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ فعال", "ask_enable"),
			tgbotapi.NewInlineKeyboardButtonData("⛔ غیرفعال", "ask_disable"),
		),
	)
	_, _ = b.api.Send(msg)
}

func (b *Bot) cmdListWithButtons(chatID int64) {
	list, err := b.st.ListLicenses()
	if err != nil {
		b.reply(chatID, "خطا: "+err.Error())
		return
	}
	if len(list) == 0 {
		b.reply(chatID, "هیچ لایسنس‌ای وجود ندارد")
		return
	}

	lines := []string{"آخرین لایسنس‌ها (برای جزئیات روی دکمه بزن):"}
	max := len(list)
	if max > 20 {
		max = 20
	}
	buttons := make([][]tgbotapi.InlineKeyboardButton, 0)
	for i := 0; i < max; i++ {
		it := list[i]
		lines = append(lines, fmt.Sprintf("- %s | %d/%d | enabled=%v", it.License.Key, it.Used, it.License.Limit, it.License.Enabled))
		// One button per row (keeps callback data short and UI clean)
		buttons = append(buttons, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("ℹ️ " + shortKey(it.License.Key), "info:"+it.License.Key),
		))
	}
	buttons = append(buttons, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("↩️ منو", "menu"),
	))

	msg := tgbotapi.NewMessage(chatID, strings.Join(lines, "\n"))
	msg.DisableWebPagePreview = true
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(buttons...)
	_, _ = b.api.Send(msg)
}

func shortKey(k string) string {
	// Keep button label short; full key is in callback data.
	k = strings.TrimSpace(k)
	if len(k) <= 18 {
		return k
	}
	return k[:10] + "..." + k[len(k)-6:]
}

func (b *Bot) handleNewLicenseInput(chatID int64, text string) {
	fields := strings.Fields(text)
	if len(fields) < 1 {
		b.reply(chatID, "ورودی نامعتبر")
		return
	}
	limit, err := strconv.Atoi(fields[0])
	if err != nil || limit <= 0 {
		b.reply(chatID, "limit نامعتبر است")
		return
	}
	note := strings.TrimSpace(strings.TrimPrefix(text, fields[0]))
	note = strings.TrimSpace(note)
	lic, err := b.st.CreateLicense(limit, note)
	if err != nil {
		b.reply(chatID, "خطا: "+err.Error())
		return
	}
	b.setState(chatID, stateNone)
	b.reply(chatID, fmt.Sprintf("License ساخته شد:\n%s\nLimit: %d\nEnabled: %v\nNote: %s", lic.Key, lic.Limit, lic.Enabled, safeNote(lic.Note)))
	b.sendMenu(chatID, "")
}

func (b *Bot) handleSetLimitInput(chatID int64, text string) {
	fields := strings.Fields(text)
	if len(fields) != 2 {
		b.reply(chatID, "ورودی نامعتبر. فرمت: <license> <limit>")
		return
	}
	limit, err := strconv.Atoi(fields[1])
	if err != nil || limit <= 0 {
		b.reply(chatID, "limit نامعتبر است")
		return
	}
	b.setState(chatID, stateNone)
	b.cmdSetLimit(chatID, fields)
	b.sendMenu(chatID, "")
}

func (b *Bot) answerCallback(id string, text string) error {
	cb := tgbotapi.NewCallback(id, text)
	_, err := b.api.Request(cb)
	return err
}

func (b *Bot) setState(chatID int64, st pendingState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if st == stateNone {
		delete(b.states, chatID)
		return
	}
	b.states[chatID] = st
}

func (b *Bot) getState(chatID int64) pendingState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.states[chatID]
}

func (b *Bot) cmdNew(chatID int64, raw string, args []string) {
	if len(args) < 1 {
		b.reply(chatID, "استفاده: /new <limit> [note]")
		return
	}
	limit, err := strconv.Atoi(args[0])
	if err != nil || limit <= 0 {
		b.reply(chatID, "limit نامعتبر است")
		return
	}

	// note = rest of message after first arg
	note := ""
	idx := strings.Index(raw, args[0])
	if idx >= 0 {
		rest := strings.TrimSpace(raw[idx+len(args[0]):])
		rest = strings.TrimSpace(strings.TrimPrefix(rest, " "))
		note = strings.TrimSpace(rest)
	}
	lic, err := b.st.CreateLicense(limit, note)
	if err != nil {
		b.reply(chatID, "خطا: "+err.Error())
		return
	}
	b.reply(chatID, fmt.Sprintf("License ساخته شد:\n%s\nLimit: %d\nEnabled: %v\nNote: %s", lic.Key, lic.Limit, lic.Enabled, safeNote(lic.Note)))
}

func (b *Bot) cmdInfo(chatID int64, args []string) {
	if len(args) != 1 {
		b.reply(chatID, "استفاده: /info <license>")
		return
	}
	info, err := b.st.GetInfo(args[0])
	if err != nil {
		b.reply(chatID, "خطا: "+err.Error())
		return
	}
	lines := []string{
		"License: " + info.License.Key,
		fmt.Sprintf("Enabled: %v", info.License.Enabled),
		fmt.Sprintf("Limit: %d", info.License.Limit),
		fmt.Sprintf("Used: %d", info.Used),
		"Note: " + safeNote(info.License.Note),
		"Created: " + info.License.CreatedAt.Format(time.RFC3339),
	}
	if len(info.Bindings) > 0 {
		lines = append(lines, "Servers:")
		max := len(info.Bindings)
		if max > 30 {
			max = 30
		}
		for i := 0; i < max; i++ {
			s := info.Bindings[i]
			lines = append(lines, fmt.Sprintf("- %s (last: %s)", s.ServerID, s.LastSeen.Format(time.RFC3339)))
		}
		if len(info.Bindings) > max {
			lines = append(lines, fmt.Sprintf("... (%d more)", len(info.Bindings)-max))
		}
	}
	b.reply(chatID, strings.Join(lines, "\n"))
}

func (b *Bot) cmdList(chatID int64) {
	list, err := b.st.ListLicenses()
	if err != nil {
		b.reply(chatID, "خطا: "+err.Error())
		return
	}
	if len(list) == 0 {
		b.reply(chatID, "هیچ لایسنس‌ای وجود ندارد")
		return
	}
	lines := []string{"Licenses:"}
	max := len(list)
	if max > 50 {
		max = 50
	}
	for i := 0; i < max; i++ {
		it := list[i]
		lines = append(lines, fmt.Sprintf("- %s | %d/%d | enabled=%v", it.License.Key, it.Used, it.License.Limit, it.License.Enabled))
	}
	if len(list) > max {
		lines = append(lines, fmt.Sprintf("... (%d more)", len(list)-max))
	}
	b.reply(chatID, strings.Join(lines, "\n"))
}

func (b *Bot) cmdSetLimit(chatID int64, args []string) {
	if len(args) != 2 {
		b.reply(chatID, "استفاده: /setlimit <license> <limit>")
		return
	}
	limit, err := strconv.Atoi(args[1])
	if err != nil || limit <= 0 {
		b.reply(chatID, "limit نامعتبر است")
		return
	}
	lic, err := b.st.SetLimit(args[0], limit)
	if err != nil {
		b.reply(chatID, "خطا: "+err.Error())
		return
	}
	b.reply(chatID, fmt.Sprintf("OK\n%s\nNew limit: %d", lic.Key, lic.Limit))
}

func (b *Bot) cmdEnable(chatID int64, args []string, enabled bool) {
	if len(args) != 1 {
		if enabled {
			b.reply(chatID, "استفاده: /enable <license>")
		} else {
			b.reply(chatID, "استفاده: /disable <license>")
		}
		return
	}
	lic, err := b.st.SetEnabled(args[0], enabled)
	if err != nil {
		b.reply(chatID, "خطا: "+err.Error())
		return
	}
	b.reply(chatID, fmt.Sprintf("OK\n%s\nEnabled: %v", lic.Key, lic.Enabled))
}

func (b *Bot) reply(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.DisableWebPagePreview = true
	_, _ = b.api.Send(msg)
}

func helpText() string {
	return "برای مدیریت از دکمه‌های منو استفاده کن. /menu"
}

func safeNote(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
