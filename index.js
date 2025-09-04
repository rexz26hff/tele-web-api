const express = require("express");
const { Telegraf } = require("telegraf");

const app = express();
app.use(express.json());

const BOT_TOKEN = process.env.BOT_TOKEN; // isi di Railway nanti
const OWNER_ID = process.env.OWNER_ID;   // isi dengan ID Telegram lo
const bot = new Telegraf(BOT_TOKEN);

// Endpoint untuk Web Panel kirim bug
app.post("/send-bug", async (req, res) => {
  const { target, bugType } = req.body;
  if (!target || !bugType) {
    return res.status(400).json({ success: false, message: "Target dan bugType wajib diisi" });
  }

  try {
    await bot.telegram.sendMessage(OWNER_ID,
      `Incoming Bug Request:
Target: ${target}
Type: ${bugType}`
    );

    // Tambahkan logika bug asli di sini (DocXLocXimageXvideo atau lainnya)

    return res.json({ success: true, message: "Bug request diteruskan ke Bot Telegram" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      success: false,
      message: "Gagal mengirim ke Bot",
      error: err.message
    });
  }
});

// Test endpoint
app.get("/", (req, res) => {
  res.send("🟢 API tele-web-api is running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API jalan di port ${PORT}`));
