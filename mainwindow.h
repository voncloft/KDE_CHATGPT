#pragma once

#include <QMainWindow>
#include <QByteArray>

class QTabWidget;
class QTextBrowser;
class QPlainTextEdit;
class QPushButton;
class QLabel;
class QComboBox;

class QNetworkAccessManager;
class QNetworkReply;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void onSendClicked();
    void onReplyReadyRead();
    void onReplyFinished();
    void onSetApiKey();
    void onNewChat();

private:
    // UI
    void setStatus(const QString& text);
    void appendChatMessage(const QString& who, const QString& text);
    void logMessage(const QString& text);

    void startAssistantMessage();
    void appendAssistantDelta(const QString& delta);
    void setAssistantFullText(const QString& text);
    void finalizeAssistantMessage();

    // API key
    QString apiKeyPath() const;
    QString loadApiKeyFromDisk() const;
    bool saveApiKeyToDisk(const QString& key, QString* errOut = nullptr);
    QString getApiKeyOrEmpty() const;

    // Network
    void sendToOpenAI(const QString& userText);

private:
    // Tabs
    QTabWidget*     m_tabs = nullptr;

    // Tab 1: Prompt page
    QWidget*        m_promptTab = nullptr;
    QComboBox*      m_modelBox = nullptr;
    QLabel*         m_status = nullptr;
    QPlainTextEdit* m_responseBox = nullptr;
    QPlainTextEdit* m_questionBox = nullptr;
    QPushButton*    m_sendBtn = nullptr;

    // Tab 2: Chat transcript
    QTextBrowser*   m_chatView = nullptr;

    // Tab 3: Logs
    QPlainTextEdit* m_logView = nullptr;

    // Networking
    QNetworkAccessManager* m_net = nullptr;
    QNetworkReply*         m_reply = nullptr;

    // Streaming state
    QByteArray m_sseBuffer;
    bool       m_inAssistant = false;
    QString    m_assistantText;

    // Conversation state (the real fix)
    QString    m_lastResponseId;     // previous_response_id for next call
    QString    m_pendingResponseId;  // set from response.created while streaming
};
