#include "mainwindow.h"

#include <QTabWidget>
#include <QTextBrowser>
#include <QPlainTextEdit>
#include <QLabel>
#include <QComboBox>
#include <QGroupBox>
#include <QListWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QScrollBar>
#include <QTextCursor>
#include <QSizePolicy>

#include <QMenuBar>
#include <QAction>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileDialog>

#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QFileDevice>
#include <QKeyEvent>
#include <QImage>
#include <QBuffer>

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

/* ---------------- helpers ---------------- */

static QString nowTs()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
}

static QString humanBytes(qint64 b)
{
    const double kb = 1024.0;
    const double mb = kb * 1024.0;
    if (b >= (qint64)mb) return QString::number(b / mb, 'f', 2) + " MB";
    if (b >= (qint64)kb) return QString::number(b / kb, 'f', 2) + " KB";
    return QString::number(b) + " B";
}

static QByteArray sseExtractData(const QByteArray& eventBlock)
{
    const QList<QByteArray> lines = eventBlock.split('\n');
    QByteArray data;
    for (QByteArray line : lines) {
        line = line.trimmed();
        if (line.startsWith("data:")) {
            QByteArray d = line.mid(5).trimmed();
            if (!data.isEmpty()) data.append('\n');
            data.append(d);
        }
    }
    return data;
}

static QGroupBox* makeGroupBox(const QString& title, QWidget* inner)
{
    auto* gb = new QGroupBox(title);
    gb->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    auto* v = new QVBoxLayout(gb);
    v->setContentsMargins(12, 18, 12, 12);
    v->setSpacing(10);
    v->addWidget(inner, 1);

    return gb;
}

static qint64 totalAttachBytes(const QVector<Attachment>& atts)
{
    qint64 t = 0;
    for (const auto& a : atts) t += a.bytes;
    return t;
}

/* ---------------- ctor/dtor ---------------- */

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("ChatGPT KDE UI (Qt6 + OpenAI)");
    resize(1250, 880);

    m_net = new QNetworkAccessManager(this);

    // Menu
    {
        auto* fileMenu = menuBar()->addMenu("&File");

        auto* setKey = new QAction("Set API Key…", this);
        connect(setKey, &QAction::triggered, this, &MainWindow::onSetApiKey);
        fileMenu->addAction(setKey);

        fileMenu->addSeparator();

        auto* attach = new QAction("Attach Files…", this);
        connect(attach, &QAction::triggered, this, &MainWindow::onAttachFiles);
        fileMenu->addAction(attach);

        auto* clearAttach = new QAction("Clear Attachments", this);
        connect(clearAttach, &QAction::triggered, this, &MainWindow::onClearAttachments);
        fileMenu->addAction(clearAttach);

        fileMenu->addSeparator();

        auto* newChat = new QAction("New Chat", this);
        connect(newChat, &QAction::triggered, this, &MainWindow::onNewChat);
        fileMenu->addAction(newChat);

        auto* saveConv = new QAction("Save Conversation…", this);
        connect(saveConv, &QAction::triggered, this, &MainWindow::onSaveConversation);
        fileMenu->addAction(saveConv);

        auto* delConv = new QAction("Delete Conversation…", this);
        connect(delConv, &QAction::triggered, this, &MainWindow::onDeleteConversation);
        fileMenu->addAction(delConv);

        fileMenu->addSeparator();
        fileMenu->addAction("Quit", this, &QWidget::close);
    }

    // Tabs
    m_tabs = new QTabWidget;
    setCentralWidget(m_tabs);

    /* ---------------- Prompt tab ---------------- */

    m_promptTab = new QWidget;

    m_modelBox = new QComboBox;
    m_modelBox->addItems({ "gpt-4o-mini", "gpt-4o", "gpt-5" });
    m_modelBox->setCurrentText("gpt-4o-mini");

    m_convBox = new QComboBox;
    connect(m_convBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onConversationChanged);

    m_status = new QLabel("Ready.");
    m_status->setStyleSheet("color:#444; padding-left:6px;");

    m_responseBox = new QPlainTextEdit;
    m_responseBox->setReadOnly(true);
    m_responseBox->setPlaceholderText("Assistant response will stream here…");
    m_responseBox->setMinimumHeight(320);
    m_responseBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    m_questionBox = new QPlainTextEdit;
    m_questionBox->setPlaceholderText("Type your question…");
    m_questionBox->setMinimumHeight(220);
    m_questionBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_questionBox->installEventFilter(this);

    m_hintLabel = new QLabel("Enter = send | Shift+Enter = newline | Attach: text/images (PDF disabled)");
    m_hintLabel->setStyleSheet("color:#666; font-size:12px; padding-left:2px;");

    m_attachList = new QListWidget;
    m_attachList->setMinimumHeight(90);
    m_attachList->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding);

    auto* topRow = new QWidget;
    {
        auto* h = new QHBoxLayout(topRow);
        h->setContentsMargins(0, 0, 0, 0);
        h->setSpacing(10);

        h->addWidget(new QLabel("Model:"), 0);
        h->addWidget(m_modelBox, 0);

        h->addSpacing(12);

        h->addWidget(new QLabel("Conversation:"), 0);
        h->addWidget(m_convBox, 1);

        h->addStretch(1);
        h->addWidget(m_status, 0);
    }

    m_responseGroup = makeGroupBox("Your Response", m_responseBox);

    auto* questionInner = new QWidget;
    {
        auto* v = new QVBoxLayout(questionInner);
        v->setContentsMargins(0, 0, 0, 0);
        v->setSpacing(8);

        v->addWidget(m_questionBox, 1);

        auto* attachLabel = new QLabel("Attachments (sticky until cleared):");
        attachLabel->setStyleSheet("color:#444; font-size:12px; font-weight:600;");
        v->addWidget(attachLabel, 0);

        v->addWidget(m_attachList, 0);
        v->addWidget(m_hintLabel, 0, Qt::AlignLeft);
    }
    m_questionGroup = makeGroupBox("My Question", questionInner);

    {
        auto* v = new QVBoxLayout(m_promptTab);
        v->setContentsMargins(14, 14, 14, 14);
        v->setSpacing(12);
        v->addWidget(topRow, 0);
        v->addWidget(m_responseGroup, 2);
        v->addWidget(m_questionGroup, 2);
    }

    m_tabs->addTab(m_promptTab, "Prompt");

    /* ---------------- Chat tab ---------------- */

    m_chatView = new QTextBrowser;
    m_chatView->setOpenExternalLinks(true);
    m_chatView->setStyleSheet("QTextBrowser { padding: 12px; font-size: 14px; }");
    m_tabs->addTab(m_chatView, "Chat");

    /* ---------------- Logs tab ---------------- */

    m_logView = new QPlainTextEdit;
    m_logView->setReadOnly(true);
    m_logView->setStyleSheet("QPlainTextEdit { padding: 10px; font-family: monospace; font-size: 12px; }");
    m_tabs->addTab(m_logView, "Logs");

    // Init storage + dropdown
    ensureConvDirs();
    refreshConversationDropdown();
    refreshAttachmentListUI();

    // Startup notice
    if (loadApiKeyFromDisk().isEmpty()) {
        appendChatMessage("system",
                          "Wired for OpenAI Responses API (streaming).\n"
                          "No API key found at ~/.api_key.\n"
                          "Use File → Set API Key…");
        logMessage("API key missing (~/.api_key)");
    } else {
        appendChatMessage("system",
                          "Wired for OpenAI Responses API (streaming).\n"
                          "API key loaded from ~/.api_key.\n"
                          "Ask questions in the Prompt tab.");
        logMessage("API key loaded from: " + apiKeyPath());
    }

    onNewChat();
}

MainWindow::~MainWindow()
{
    if (m_reply) {
        m_reply->abort();
        m_reply->deleteLater();
        m_reply = nullptr;
    }
}

/* ---------------- Enter to send ---------------- */

bool MainWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_questionBox && event->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(event);
        const bool isEnter = (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter);
        const bool shift = (ke->modifiers() & Qt::ShiftModifier);

        if (isEnter && !shift) {
            const QString userText = m_questionBox->toPlainText().trimmed();
            if (!userText.isEmpty() && !m_reply) {
                appendChatMessage("you", userText);
                m_questionBox->clear();
                sendToOpenAI(userText);
            }
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

/* ---------------- UI helpers ---------------- */

void MainWindow::setStatus(const QString& text) { m_status->setText(text); }

void MainWindow::logMessage(const QString& text)
{
    m_logView->appendPlainText(QString("[%1] %2").arg(nowTs(), text));
    m_logView->verticalScrollBar()->setValue(m_logView->verticalScrollBar()->maximum());
}

void MainWindow::appendChatMessage(const QString& who, const QString& text)
{
    const QString ts = nowTs();
    m_chatLines.push_back(ChatLine{who, text, ts});

    const QString header =
        (who == "you") ? "You" :
        (who == "assistant") ? "Assistant" :
        "System";

    QString html;
    html += "<div style='margin-bottom:12px;'>";
    html += "<div style='font-weight:700; margin-bottom:4px;'>" + header.toHtmlEscaped()
         + " <span style='font-weight:400; color:#666; font-size:12px;'>(" + ts.toHtmlEscaped() + ")</span></div>";
    html += "<div style='white-space:pre-wrap;'>" + text.toHtmlEscaped() + "</div>";
    html += "</div>";

    m_chatView->append(html);
    m_chatView->verticalScrollBar()->setValue(m_chatView->verticalScrollBar()->maximum());
}

void MainWindow::rebuildChatViewFromMemory()
{
    m_chatView->clear();
    for (const auto& line : m_chatLines) {
        const QString header =
            (line.who == "you") ? "You" :
            (line.who == "assistant") ? "Assistant" :
            "System";

        QString html;
        html += "<div style='margin-bottom:12px;'>";
        html += "<div style='font-weight:700; margin-bottom:4px;'>" + header.toHtmlEscaped()
             + " <span style='font-weight:400; color:#666; font-size:12px;'>(" + line.ts.toHtmlEscaped() + ")</span></div>";
        html += "<div style='white-space:pre-wrap;'>" + line.text.toHtmlEscaped() + "</div>";
        html += "</div>";

        m_chatView->append(html);
    }
    m_chatView->verticalScrollBar()->setValue(m_chatView->verticalScrollBar()->maximum());
}

void MainWindow::refreshAttachmentListUI()
{
    m_attachList->clear();
    if (m_attachments.isEmpty()) {
        m_attachList->addItem("(no attachments)");
        return;
    }

    qint64 total = 0;
    for (const auto& a : m_attachments) {
        total += a.bytes;
        const QString kind = (a.kind == AttachKind::Text) ? "TEXT" : "IMAGE";
        m_attachList->addItem(QString("[%1] %2  (%3)").arg(kind, a.displayName, humanBytes(a.bytes)));
    }
    m_attachList->addItem(QString("Total attachment bytes: %1").arg(humanBytes(total)));
}

/* ---------------- API key ---------------- */

QString MainWindow::apiKeyPath() const { return QDir::homePath() + "/.api_key"; }

QString MainWindow::loadApiKeyFromDisk() const
{
    QFile f(apiKeyPath());
    if (!f.exists()) return {};
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};
    return QString::fromUtf8(f.readAll()).trimmed();
}

bool MainWindow::saveApiKeyToDisk(const QString& key, QString* errOut)
{
    QFile f(apiKeyPath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (errOut) *errOut = f.errorString();
        return false;
    }
    f.write(key.toUtf8());
    f.write("\n");
    f.flush();
    f.close();
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

QString MainWindow::getApiKeyOrEmpty() const { return loadApiKeyFromDisk(); }

void MainWindow::onSetApiKey()
{
    bool ok = false;
    const QString key = QInputDialog::getText(
        this,
        "Set API Key",
        "Paste your OpenAI API key.\nIt will be saved to ~/.api_key (permissions 600).",
        QLineEdit::Password,
        "",
        &ok
    ).trimmed();

    if (!ok) return;
    if (key.isEmpty()) { appendChatMessage("system", "API key was empty. Not saved."); return; }

    QString err;
    if (!saveApiKeyToDisk(key, &err)) {
        appendChatMessage("system", "Failed to save API key to ~/.api_key.");
        logMessage("Failed to save API key: " + err);
        return;
    }

    appendChatMessage("system", "API key saved to ~/.api_key.");
    logMessage("API key saved to: " + apiKeyPath());
}

/* ---------------- Conversation storage ---------------- */

QString MainWindow::convRootDir() const { return QDir::homePath() + "/.chatgpt_kde"; }

void MainWindow::ensureConvDirs()
{
    QDir d(convRootDir());
    if (!d.exists()) d.mkpath(".");
    if (!d.exists("conversations")) d.mkpath("conversations");
}

QString MainWindow::sanitizeConvName(const QString& name) const
{
    QString s = name.trimmed();
    s.replace("/", "_");
    s.replace("\\", "_");
    s.replace("..", "_");
    if (s.isEmpty()) s = "conversation";
    return s;
}

QString MainWindow::convFilePathForName(const QString& name) const
{
    return convRootDir() + "/conversations/" + sanitizeConvName(name) + ".json";
}

void MainWindow::refreshConversationDropdown()
{
    m_suppressConvChange = true;

    const QString prev = m_currentConversationName;

    m_convBox->clear();
    m_convBox->addItem("(New chat)");

    QDir d(convRootDir() + "/conversations");
    const QStringList files = d.entryList(QStringList() << "*.json", QDir::Files, QDir::Name);
    for (QString f : files) {
        if (f.endsWith(".json")) f.chop(5);
        m_convBox->addItem(f);
    }

    int idx = 0;
    if (!prev.isEmpty()) {
        const int found = m_convBox->findText(prev);
        if (found >= 0) idx = found;
    }
    m_convBox->setCurrentIndex(idx);

    m_suppressConvChange = false;
}

bool MainWindow::saveConversationToDisk(const QString& name, QString* errOut)
{
    ensureConvDirs();

    QJsonObject root;
    root["name"] = name;
    root["last_response_id"] = m_lastResponseId;

    QJsonArray lines;
    for (const auto& cl : m_chatLines) {
        QJsonObject o;
        o["who"] = cl.who;
        o["text"] = cl.text;
        o["ts"] = cl.ts;
        lines.append(o);
    }
    root["chat_lines"] = lines;

    const QByteArray bytes = QJsonDocument(root).toJson(QJsonDocument::Indented);

    QFile f(convFilePathForName(name));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (errOut) *errOut = f.errorString();
        return false;
    }
    if (f.write(bytes) != bytes.size()) {
        if (errOut) *errOut = f.errorString();
        return false;
    }
    f.flush();
    f.close();
    return true;
}

bool MainWindow::loadConversationFromDisk(const QString& name, QString* errOut)
{
    QFile f(convFilePathForName(name));
    if (!f.open(QIODevice::ReadOnly)) {
        if (errOut) *errOut = f.errorString();
        return false;
    }

    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        if (errOut) *errOut = "Invalid JSON";
        return false;
    }

    const QJsonObject root = doc.object();
    m_lastResponseId = root.value("last_response_id").toString();
    m_pendingResponseId.clear();

    m_chatLines.clear();
    const QJsonArray lines = root.value("chat_lines").toArray();
    for (const auto& v : lines) {
        const QJsonObject o = v.toObject();
        ChatLine cl;
        cl.who = o.value("who").toString();
        cl.text = o.value("text").toString();
        cl.ts  = o.value("ts").toString();
        m_chatLines.push_back(cl);
    }

    rebuildChatViewFromMemory();
    m_responseBox->clear();
    m_questionBox->clear();
    setStatus("Ready.");
    return true;
}

bool MainWindow::deleteConversationFromDisk(const QString& name, QString* errOut)
{
    QFile f(convFilePathForName(name));
    if (!f.exists()) return true;
    if (!f.remove()) {
        if (errOut) *errOut = f.errorString();
        return false;
    }
    return true;
}

/* ---------------- Menu actions ---------------- */

void MainWindow::onNewChat()
{
    m_currentConversationName.clear();
    m_lastResponseId.clear();
    m_pendingResponseId.clear();

    m_sseBuffer.clear();
    m_inAssistant = false;
    m_assistantText.clear();

    m_chatLines.clear();
    m_chatView->clear();

    appendChatMessage("system", "New chat started (memory cleared).");
    logMessage("New chat: previous_response_id cleared.");

    m_responseBox->clear();
    m_questionBox->clear();
    setStatus("Ready.");

    refreshConversationDropdown();
    m_convBox->setCurrentIndex(0);
}

void MainWindow::onSaveConversation()
{
    bool ok = false;
    QString suggested = m_currentConversationName.isEmpty() ? "conversation" : m_currentConversationName;

    const QString name = QInputDialog::getText(
        this,
        "Save Conversation",
        "Conversation name:",
        QLineEdit::Normal,
        suggested,
        &ok
    ).trimmed();

    if (!ok || name.isEmpty()) return;

    QString err;
    if (!saveConversationToDisk(name, &err)) {
        QMessageBox::warning(this, "Save failed", "Failed to save conversation:\n" + err);
        logMessage("Save failed: " + err);
        return;
    }

    m_currentConversationName = sanitizeConvName(name);
    appendChatMessage("system", "Conversation saved as: " + m_currentConversationName);
    logMessage("Conversation saved: " + m_currentConversationName);

    refreshConversationDropdown();
    const int idx = m_convBox->findText(m_currentConversationName);
    if (idx >= 0) m_convBox->setCurrentIndex(idx);
}

void MainWindow::onDeleteConversation()
{
    const QString name = m_convBox->currentText();
    if (name.isEmpty() || name == "(New chat)") {
        QMessageBox::information(this, "Delete conversation", "Select a saved conversation first.");
        return;
    }

    const auto res = QMessageBox::question(
        this,
        "Delete Conversation",
        "Delete conversation '" + name + "'?\n(This removes the saved file.)"
    );
    if (res != QMessageBox::Yes) return;

    QString err;
    if (!deleteConversationFromDisk(name, &err)) {
        QMessageBox::warning(this, "Delete failed", "Failed to delete conversation:\n" + err);
        logMessage("Delete failed: " + err);
        return;
    }

    logMessage("Conversation deleted: " + name);
    if (m_currentConversationName == name) onNewChat();
    else refreshConversationDropdown();
}

void MainWindow::onConversationChanged(int index)
{
    if (m_suppressConvChange) return;

    if (index <= 0) {
        onNewChat();
        return;
    }

    const QString name = m_convBox->itemText(index);
    QString err;
    if (!loadConversationFromDisk(name, &err)) {
        QMessageBox::warning(this, "Load failed", "Failed to load conversation:\n" + err);
        logMessage("Load failed: " + err);
        return;
    }

    m_currentConversationName = name;
    appendChatMessage("system", "Loaded conversation: " + name);
    logMessage("Loaded conversation: " + name + " (previous_response_id " + (m_lastResponseId.isEmpty() ? "empty" : "set") + ")");
}

/* ---------------- Attachments (text/images only) ---------------- */

void MainWindow::onAttachFiles()
{
    const QStringList paths = QFileDialog::getOpenFileNames(
        this,
        "Attach files (text/images)",
        QDir::homePath(),
        "Text/Images (*.txt *.md *.log *.json *.yaml *.yml *.ini *.cfg *.conf *.csv *.cpp *.c *.h *.hpp *.cs *.py *.sh *.js *.ts *.java *.rs *.go *.png *.jpg *.jpeg *.webp *.pdf);;All Files (*)"
    );

    if (paths.isEmpty()) return;

    int added = 0;
    for (const QString& p : paths) {
        QString err;
        if (!addAttachmentFromPath(p, &err)) {
            appendChatMessage("system", "Attach failed for " + QFileInfo(p).fileName() + ":\n" + err);
            logMessage("Attach failed: " + p + " :: " + err);
        } else {
            added++;
        }
    }

    refreshAttachmentListUI();
    logMessage(QString("Attach done: added %1, total %2").arg(added).arg(m_attachments.size()));
}

void MainWindow::onClearAttachments()
{
    m_attachments.clear();
    refreshAttachmentListUI();
    logMessage("Attachments cleared.");
}

bool MainWindow::addAttachmentFromPath(const QString& path, QString* errOut)
{
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile()) {
        if (errOut) *errOut = "Not a file.";
        return false;
    }

    const QString ext = fi.suffix().toLower();
    if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "webp")
        return addImageAttachment(path, errOut);

    if (ext == "pdf") {
        if (errOut) *errOut = "PDF disabled. (Install/link QtPdf or use a PDF-to-image backend.)";
        return false;
    }

    return addTextAttachment(path, errOut);
}

bool MainWindow::addTextAttachment(const QString& path, QString* errOut)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (errOut) *errOut = f.errorString();
        return false;
    }
    QByteArray bytes = f.readAll();
    f.close();

    const qint64 newTotal = totalAttachBytes(m_attachments) + bytes.size();
    if (newTotal > MAX_TOTAL_ATTACH_BYTES) {
        if (errOut) *errOut = QString("Too large. Total attachment cap is %1.").arg(humanBytes(MAX_TOTAL_ATTACH_BYTES));
        return false;
    }

    QString text = QString::fromUtf8(bytes);
    if (text.size() > MAX_TEXT_CHARS)
        text = text.left(MAX_TEXT_CHARS) + "\n\n[TRUNCATED]";

    Attachment a;
    a.kind = AttachKind::Text;
    a.path = path;
    a.displayName = QFileInfo(path).fileName();
    a.mime = "text/plain";
    a.bytes = bytes.size();
    a.text = text;

    m_attachments.push_back(a);
    return true;
}

bool MainWindow::addImageAttachment(const QString& path, QString* errOut)
{
    QImage img(path);
    if (img.isNull()) {
        if (errOut) *errOut = "Failed to load image.";
        return false;
    }

    QByteArray outBytes;
    QBuffer buf(&outBytes);
    buf.open(QIODevice::WriteOnly);
    if (!img.save(&buf, "PNG")) {
        if (errOut) *errOut = "Failed to encode image as PNG.";
        return false;
    }

    const qint64 newTotal = totalAttachBytes(m_attachments) + outBytes.size();
    if (newTotal > MAX_TOTAL_ATTACH_BYTES) {
        if (errOut) *errOut = QString("Too large after encoding. Total attachment cap is %1.").arg(humanBytes(MAX_TOTAL_ATTACH_BYTES));
        return false;
    }

    Attachment a;
    a.kind = AttachKind::Image;
    a.path = path;
    a.displayName = QFileInfo(path).fileName();
    a.mime = "image/png";
    a.bytes = outBytes.size();
    a.imageBase64 = QString::fromLatin1(outBytes.toBase64());

    m_attachments.push_back(a);
    return true;
}

/* ---------------- Streaming display ---------------- */

void MainWindow::startAssistantMessage()
{
    m_inAssistant = true;
    m_assistantText.clear();
    m_responseBox->clear();
}

void MainWindow::appendAssistantDelta(const QString& delta)
{
    if (!m_inAssistant) startAssistantMessage();
    m_assistantText += delta;
    m_responseBox->setPlainText(m_assistantText);
    auto c = m_responseBox->textCursor();
    c.movePosition(QTextCursor::End);
    m_responseBox->setTextCursor(c);
}

void MainWindow::setAssistantFullText(const QString& text)
{
    if (!m_inAssistant) startAssistantMessage();
    m_assistantText = text;
    m_responseBox->setPlainText(m_assistantText);
    auto c = m_responseBox->textCursor();
    c.movePosition(QTextCursor::End);
    m_responseBox->setTextCursor(c);
}

void MainWindow::finalizeAssistantMessage()
{
    if (!m_inAssistant) return;
    m_inAssistant = false;

    const QString finalText = m_assistantText.trimmed();
    if (!finalText.isEmpty())
        appendChatMessage("assistant", finalText);

    if (!m_pendingResponseId.isEmpty()) {
        m_lastResponseId = m_pendingResponseId;
        m_pendingResponseId.clear();
        logMessage("Memory updated: previous_response_id set for next turn.");
    }
}

/* ---------------- OpenAI network ---------------- */

void MainWindow::sendToOpenAI(const QString& userText)
{
    const QString apiKey = getApiKeyOrEmpty();
    if (apiKey.isEmpty()) {
        setStatus("ERROR: No API key.");
        appendChatMessage("system", "No API key found. File → Set API Key…");
        logMessage("Refused request: missing API key.");
        return;
    }

    if (m_reply) {
        setStatus("Busy…");
        return;
    }

    const QString model = m_modelBox->currentText();

    QNetworkRequest req(QUrl("https://api.openai.com/v1/responses"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Accept", "text/event-stream");
    req.setRawHeader("Authorization", QByteArray("Bearer ") + apiKey.toUtf8());

    QJsonObject body;
    body["model"] = model;
    body["stream"] = true;
    body["store"] = true;
    if (!m_lastResponseId.isEmpty())
        body["previous_response_id"] = m_lastResponseId;

    QJsonArray content;

    { QJsonObject part; part["type"]="input_text"; part["text"]=userText; content.append(part); }

    for (const auto& a : m_attachments) {
        if (a.kind != AttachKind::Text) continue;
        QJsonObject part;
        part["type"] = "input_text";
        part["text"] = QString("=== ATTACHMENT: %1 ===\n%2\n=== END ATTACHMENT: %1 ===")
                           .arg(a.displayName, a.text);
        content.append(part);
    }

    for (const auto& a : m_attachments) {
        if (a.kind != AttachKind::Image) continue;

        { QJsonObject label; label["type"]="input_text"; label["text"]=QString("Image attachment: %1").arg(a.displayName); content.append(label); }
        QJsonObject part;
        part["type"] = "input_image";
        part["image_base64"] = a.imageBase64;
        content.append(part);
    }

    QJsonArray input;
    QJsonObject msg;
    msg["role"] = "user";
    msg["content"] = content;
    input.append(msg);
    body["input"] = input;

    const QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);

    setStatus("Sending…");
    m_sseBuffer.clear();
    m_pendingResponseId.clear();
    startAssistantMessage();

    logMessage(QString("POST /v1/responses model=%1 previous_response_id=%2 attachments=%3 bytes=%4")
               .arg(model)
               .arg(m_lastResponseId.isEmpty() ? "(none)" : "(set)")
               .arg(m_attachments.size())
               .arg(humanBytes(totalAttachBytes(m_attachments))));

    m_reply = m_net->post(req, payload);
    connect(m_reply, &QNetworkReply::readyRead, this, &MainWindow::onReplyReadyRead);
    connect(m_reply, &QNetworkReply::finished, this, &MainWindow::onReplyFinished);
}

void MainWindow::onReplyReadyRead()
{
    if (!m_reply) return;
    m_sseBuffer += m_reply->readAll();

    while (true) {
        const int sep = m_sseBuffer.indexOf("\n\n");
        if (sep < 0) break;

        const QByteArray eventBlock = m_sseBuffer.left(sep);
        m_sseBuffer.remove(0, sep + 2);

        const QByteArray data = sseExtractData(eventBlock);
        if (data.isEmpty()) continue;

        if (data == "[DONE]") {
            setStatus("Done.");
            finalizeAssistantMessage();
            return;
        }

        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject()) {
            logMessage("Non-JSON SSE data:\n" + QString::fromUtf8(data));
            continue;
        }

        const QJsonObject obj = doc.object();
        const QString type = obj.value("type").toString();

        if (type == "response.created") {
            const QJsonObject resp = obj.value("response").toObject();
            const QString id = resp.value("id").toString();
            if (!id.isEmpty()) {
                m_pendingResponseId = id;
                logMessage("SSE: response.created (captured response id)");
            }
        } else if (type == "response.output_text.delta") {
            const QString d = obj.value("delta").toString();
            if (!d.isEmpty()) {
                setStatus("Streaming…");
                appendAssistantDelta(d);
            }
        } else if (type == "response.output_text.done") {
            const QString t = obj.value("text").toString();
            if (!t.isEmpty()) {
                setStatus("Streaming…");
                setAssistantFullText(t);
            }
        } else if (type == "response.completed") {
            setStatus("Done.");
            finalizeAssistantMessage();
        } else if (type == "error") {
            const QJsonObject errObj = obj.value("error").toObject();
            const QString msg = errObj.value("message").toString();
            const QString code = errObj.value("code").toString();

            appendChatMessage("system", QString("OpenAI error: %1\n%2").arg(code, msg));
            logMessage("SSE error: " + QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Indented)));

            setStatus("ERROR.");
            if (m_reply) m_reply->abort();
            return;
        }
    }
}

void MainWindow::onReplyFinished()
{
    if (!m_reply) return;

    const int httpStatus = m_reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto netErr = m_reply->error();
    const QString errStr = m_reply->errorString();
    const QByteArray tail = m_reply->readAll();

    if (netErr != QNetworkReply::NoError) {
        setStatus(QString("ERROR (HTTP %1): %2").arg(httpStatus).arg(errStr));
        logMessage(QString("HTTP error %1: %2").arg(httpStatus).arg(errStr));
        if (!tail.isEmpty())
            logMessage("Body tail:\n" + QString::fromUtf8(tail));
    } else {
        setStatus("Done.");
    }

    m_reply->deleteLater();
    m_reply = nullptr;
}
