#include "mainwindow.h"

#include <QTabWidget>
#include <QTextBrowser>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QDateTime>
#include <QScrollBar>
#include <QTextCursor>

#include <QMenuBar>
#include <QAction>
#include <QInputDialog>
#include <QFile>
#include <QDir>
#include <QFileDevice>
#include <QKeyEvent>

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

/* ---------------- helpers ---------------- */

static QFrame* makeGroupFrame(const QString& title, QWidget* content)
{
    auto* frame = new QFrame;
    frame->setFrameShape(QFrame::Box);
    frame->setLineWidth(2);

    auto* titleLabel = new QLabel(title);
    titleLabel->setStyleSheet("font-weight: 600; padding: 6px;");

    auto* v = new QVBoxLayout(frame);
    v->setContentsMargins(12, 12, 12, 12);
    v->setSpacing(10);
    v->addWidget(titleLabel);
    v->addWidget(content);

    return frame;
}

static QString jsonToPretty(const QJsonObject& obj)
{
    return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Indented));
}

static QByteArray sseExtractData(const QByteArray& eventBlock)
{
    // Concatenate all "data:" lines (SSE spec)
    const QList<QByteArray> lines = eventBlock.split('\n');
    QByteArray data;
    for (QByteArray line : lines) {
        line = line.trimmed();
        if (line.startsWith("data:")) {
            QByteArray d = line.mid(5).trimmed();
            if (!data.isEmpty())
                data.append('\n');
            data.append(d);
        }
    }
    return data;
}

/* ---------------- ctor/dtor ---------------- */

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("ChatGPT KDE UI (Qt6 + OpenAI)");
    resize(1200, 760);

    m_net = new QNetworkAccessManager(this);

    // Menu
    {
        auto* fileMenu = menuBar()->addMenu("&File");

        auto* setKey = new QAction("Set API Key…", this);
        connect(setKey, &QAction::triggered, this, &MainWindow::onSetApiKey);
        fileMenu->addAction(setKey);

        auto* newChat = new QAction("New Chat (clear memory)", this);
        connect(newChat, &QAction::triggered, this, &MainWindow::onNewChat);
        fileMenu->addAction(newChat);

        fileMenu->addSeparator();
        fileMenu->addAction("Quit", this, &QWidget::close);
    }

    // Tabs
    m_tabs = new QTabWidget;
    setCentralWidget(m_tabs);

    /* -------- Tab 1: Prompt page -------- */
    m_promptTab = new QWidget;

    m_modelBox = new QComboBox;
    m_modelBox->addItem("gpt-4o-mini");
    m_modelBox->addItem("gpt-4o");
    m_modelBox->addItem("gpt-5"); // may require access
    m_modelBox->setCurrentText("gpt-4o-mini");

    m_status = new QLabel("Ready.");
    m_status->setStyleSheet("color:#444; padding-left:6px;");

    m_responseBox = new QPlainTextEdit;
    m_responseBox->setReadOnly(true);
    m_responseBox->setPlaceholderText("Assistant response will stream here...");
    m_responseBox->setMinimumHeight(340);
    m_responseBox->setStyleSheet("QPlainTextEdit { padding: 10px; }");

    m_questionBox = new QPlainTextEdit;
    m_questionBox->setPlaceholderText("Type your question... (Enter = send, Shift+Enter = newline)");
    m_questionBox->setMinimumHeight(280);
    m_questionBox->setStyleSheet("QPlainTextEdit { padding: 10px; }");
    m_questionBox->installEventFilter(this);

    m_sendBtn = new QPushButton("Send");
    m_sendBtn->setMinimumHeight(46);
    connect(m_sendBtn, &QPushButton::clicked, this, &MainWindow::onSendClicked);

    auto* topRow = new QWidget;
    {
        auto* h = new QHBoxLayout(topRow);
        h->setContentsMargins(0, 0, 0, 0);
        h->setSpacing(10);
        h->addWidget(new QLabel("Model:"));
        h->addWidget(m_modelBox, 0);
        h->addStretch(1);
        h->addWidget(m_status, 0);
    }

    auto* responseFrame = makeGroupFrame("Your Response", m_responseBox);

    auto* questionContainer = new QWidget;
    {
        auto* v = new QVBoxLayout(questionContainer);
        v->setContentsMargins(0, 0, 0, 0);
        v->setSpacing(10);
        v->addWidget(m_questionBox, 1);

        auto* h = new QHBoxLayout;
        h->addStretch(1);
        h->addWidget(m_sendBtn);
        v->addLayout(h);
    }
    auto* questionFrame = makeGroupFrame("My Question", questionContainer);

    {
        auto* v = new QVBoxLayout(m_promptTab);
        v->setContentsMargins(14, 14, 14, 14);
        v->setSpacing(12);
        v->addWidget(topRow, 0);
        v->addWidget(responseFrame, 2);
        v->addWidget(questionFrame, 2);
    }

    m_tabs->addTab(m_promptTab, "Prompt");

    /* -------- Tab 2: Chat transcript -------- */
    m_chatView = new QTextBrowser;
    m_chatView->setOpenExternalLinks(true);
    m_chatView->setStyleSheet("QTextBrowser { padding: 12px; font-size: 14px; }");
    m_tabs->addTab(m_chatView, "Chat");

    /* -------- Tab 3: Logs -------- */
    m_logView = new QPlainTextEdit;
    m_logView->setReadOnly(true);
    m_logView->setStyleSheet("QPlainTextEdit { padding: 10px; font-family: monospace; font-size: 12px; }");
    m_tabs->addTab(m_logView, "Logs");

    // Startup text goes to Chat tab
    if (loadApiKeyFromDisk().isEmpty()) {
        appendChatMessage("system",
            "Wired for OpenAI Responses API (streaming).\n"
            "No API key found at ~/.api_key.\n"
            "Use: File → Set API Key…");
        logMessage("API key missing (~/.api_key)");
    } else {
        appendChatMessage("system",
            "Wired for OpenAI Responses API (streaming).\n"
            "API key loaded from ~/.api_key.\n"
            "Ask questions in the Prompt tab.");
        logMessage("API key loaded from: " + apiKeyPath());
    }
}

MainWindow::~MainWindow()
{
    if (m_reply) {
        m_reply->abort();
        m_reply->deleteLater();
        m_reply = nullptr;
    }
}

/* ---------------- Enter-to-send ---------------- */

bool MainWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_questionBox && event->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(event);

        const bool isEnter = (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter);
        const bool shift = (ke->modifiers() & Qt::ShiftModifier);

        if (isEnter && !shift) {
            onSendClicked();
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

/* ---------------- status / chat / logs ---------------- */

void MainWindow::setStatus(const QString& text)
{
    m_status->setText(text);
}

void MainWindow::logMessage(const QString& text)
{
    const QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    m_logView->appendPlainText(QString("[%1] %2").arg(ts, text));

    auto* sb = m_logView->verticalScrollBar();
    sb->setValue(sb->maximum());
}

void MainWindow::appendChatMessage(const QString& who, const QString& text)
{
    const QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");

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

    auto* sb = m_chatView->verticalScrollBar();
    sb->setValue(sb->maximum());
}

/* ---------------- API key ---------------- */

QString MainWindow::apiKeyPath() const
{
    return QDir::homePath() + "/.api_key";
}

QString MainWindow::loadApiKeyFromDisk() const
{
    QFile f(apiKeyPath());
    if (!f.exists())
        return {};
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
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

    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner); // 600
    return true;
}

QString MainWindow::getApiKeyOrEmpty() const
{
    return loadApiKeyFromDisk();
}

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

    if (!ok)
        return;

    if (key.isEmpty()) {
        appendChatMessage("system", "API key was empty. Not saved.");
        logMessage("Set API key: empty input");
        return;
    }

    QString err;
    if (!saveApiKeyToDisk(key, &err)) {
        appendChatMessage("system", "Failed to save API key to ~/.api_key.");
        logMessage("Failed to save API key: " + err);
        return;
    }

    appendChatMessage("system", "API key saved to ~/.api_key.");
    logMessage("API key saved to: " + apiKeyPath());
}

void MainWindow::onNewChat()
{
    // This is the important part: clearing memory for next turn
    m_lastResponseId.clear();
    m_pendingResponseId.clear();

    appendChatMessage("system", "New chat started (memory cleared).");
    logMessage("Conversation state cleared (previous_response_id reset).");

    m_responseBox->clear();
    m_questionBox->clear();
    setStatus("Ready.");
}

/* ---------------- send / streaming ---------------- */

void MainWindow::onSendClicked()
{
    const QString userText = m_questionBox->toPlainText().trimmed();
    if (userText.isEmpty())
        return;

    if (m_reply) {
        setStatus("Busy (request in progress)...");
        return;
    }

    appendChatMessage("you", userText);
    m_questionBox->clear();

    sendToOpenAI(userText);
}

void MainWindow::startAssistantMessage()
{
    m_inAssistant = true;
    m_assistantText.clear();
    m_responseBox->clear();
}

void MainWindow::appendAssistantDelta(const QString& delta)
{
    if (!m_inAssistant)
        startAssistantMessage();

    m_assistantText += delta;
    m_responseBox->setPlainText(m_assistantText);

    QTextCursor c = m_responseBox->textCursor();
    c.movePosition(QTextCursor::End);
    m_responseBox->setTextCursor(c);
}

void MainWindow::setAssistantFullText(const QString& text)
{
    if (!m_inAssistant)
        startAssistantMessage();

    m_assistantText = text;
    m_responseBox->setPlainText(m_assistantText);

    QTextCursor c = m_responseBox->textCursor();
    c.movePosition(QTextCursor::End);
    m_responseBox->setTextCursor(c);
}

void MainWindow::finalizeAssistantMessage()
{
    if (!m_inAssistant)
        return;

    m_inAssistant = false;

    const QString finalText = m_assistantText.trimmed();
    if (!finalText.isEmpty())
        appendChatMessage("assistant", finalText);

    // If we got a response ID, lock it in for the next turn (this is the memory)
    if (!m_pendingResponseId.isEmpty()) {
        m_lastResponseId = m_pendingResponseId;
        m_pendingResponseId.clear();
        logMessage("Conversation chained: lastResponseId set.");
    }
}

void MainWindow::sendToOpenAI(const QString& userText)
{
    const QString apiKey = getApiKeyOrEmpty();
    if (apiKey.isEmpty()) {
        setStatus("ERROR: No API key.");
        appendChatMessage("system", "No API key found. File → Set API Key…");
        logMessage("No API key; refusing request.");
        return;
    }

    const QString model = m_modelBox->currentText();

    QNetworkRequest req(QUrl("https://api.openai.com/v1/responses"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Accept", "text/event-stream");
    req.setRawHeader("Authorization", QByteArray("Bearer ") + apiKey.toUtf8());

    // Request body
    QJsonObject body;
    body["model"] = model;
    body["stream"] = true;
    body["store"] = true;

    // THIS is the memory mechanism: chain to the previous response if we have one
    if (!m_lastResponseId.isEmpty())
        body["previous_response_id"] = m_lastResponseId;

    // Keep input simple (string content) like the docs show
    QJsonArray input;
    QJsonObject msg;
    msg["role"] = "user";
    msg["content"] = userText;
    input.append(msg);
    body["input"] = input;

    const QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);

    setStatus("Sending...");
    m_sendBtn->setEnabled(false);

    m_sseBuffer.clear();
    m_pendingResponseId.clear();
    startAssistantMessage();

    logMessage(QString("POST /v1/responses model=%1 stream=true previous_response_id=%2")
               .arg(model)
               .arg(m_lastResponseId.isEmpty() ? "(none)" : "(set)"));

    m_reply = m_net->post(req, payload);
    connect(m_reply, &QNetworkReply::readyRead, this, &MainWindow::onReplyReadyRead);
    connect(m_reply, &QNetworkReply::finished, this, &MainWindow::onReplyFinished);
}

void MainWindow::onReplyReadyRead()
{
    if (!m_reply)
        return;

    m_sseBuffer += m_reply->readAll();

    while (true) {
        int sep = m_sseBuffer.indexOf("\n\n");
        if (sep < 0)
            break;

        const QByteArray eventBlock = m_sseBuffer.left(sep);
        m_sseBuffer.remove(0, sep + 2);

        const QByteArray data = sseExtractData(eventBlock);
        if (data.isEmpty())
            continue;

        if (data == "[DONE]") {
            setStatus("Done.");
            finalizeAssistantMessage();
            logMessage("SSE: [DONE]");
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
                logMessage("SSE: response.created id captured");
            }
        } else if (type == "response.output_text.delta") {
            const QString d = obj.value("delta").toString();
            if (!d.isEmpty()) {
                setStatus("Streaming...");
                appendAssistantDelta(d);
            }
        } else if (type == "response.output_text.done") {
            const QString t = obj.value("text").toString();
            if (!t.isEmpty()) {
                setStatus("Streaming...");
                setAssistantFullText(t);
            }
        } else if (type == "response.completed") {
            setStatus("Done.");
            finalizeAssistantMessage();
            logMessage("SSE: response.completed");
        } else if (type == "error") {
            const QJsonObject errObj = obj.value("error").toObject();
            const QString msg = errObj.value("message").toString();
            const QString code = errObj.value("code").toString();

            appendChatMessage("system", QString("OpenAI error: %1\n%2").arg(code, msg));
            logMessage("SSE error raw:\n" + jsonToPretty(obj));

            setStatus("ERROR.");
            if (m_reply) m_reply->abort();
            return;
        } else {
            // Unknown event types -> Logs only
            logMessage("SSE event type=" + type + "\n" + jsonToPretty(obj));
        }
    }
}

void MainWindow::onReplyFinished()
{
    if (!m_reply)
        return;

    const int httpStatus = m_reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto netErr = m_reply->error();
    const QString errStr = m_reply->errorString();
    const QByteArray leftover = m_reply->readAll(); // any remaining bytes

    if (netErr != QNetworkReply::NoError) {
        setStatus(QString("ERROR (HTTP %1): %2").arg(httpStatus).arg(errStr));
        appendChatMessage("system", QString("Request finished with error.\nHTTP %1\n%2").arg(httpStatus).arg(errStr));

        if (!leftover.isEmpty())
            logMessage("HTTP body (tail):\n" + QString::fromUtf8(leftover));
        else
            logMessage(QString("Request finished with error. HTTP %1: %2").arg(httpStatus).arg(errStr));
    } else {
        setStatus("Done.");
    }

    m_reply->deleteLater();
    m_reply = nullptr;
    m_sendBtn->setEnabled(true);
}
