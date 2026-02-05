#pragma once

#include <QMainWindow>
#include <QByteArray>
#include <QVector>

class QTabWidget;
class QTextBrowser;
class QPlainTextEdit;
class QLabel;
class QComboBox;
class QGroupBox;

class QNetworkAccessManager;
class QNetworkReply;

struct ChatLine {
    QString who;   // "system" | "you" | "assistant"
    QString text;
    QString ts;    // timestamp string
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void onReplyReadyRead();
    void onReplyFinished();

    void onSetApiKey();
    void onNewChat();

    void onSaveConversation();
    void onDeleteConversation();
    void onConversationChanged(int index);

private:
    // UI
    void setStatus(const QString& text);
    void appendChatMessage(const QString& who, const QString& text);
    void logMessage(const QString& text);
    void rebuildChatViewFromMemory();

    void startAssistantMessage();
    void appendAssistantDelta(const QString& delta);
    void setAssistantFullText(const QString& text);
    void finalizeAssistantMessage();

    // API key
    QString apiKeyPath() const;
    QString loadApiKeyFromDisk() const;
    bool saveApiKeyToDisk(const QString& key, QString* errOut = nullptr);
    QString getApiKeyOrEmpty() const;

    // Conversations (saved)
    QString convRootDir() const;
    QString sanitizeConvName(const QString& name) const;
    QString convFilePathForName(const QString& name) const;
    void ensureConvDirs();
    void refreshConversationDropdown();

    bool saveConversationToDisk(const QString& name, QString* errOut = nullptr);
    bool loadConversationFromDisk(const QString& name, QString* errOut = nullptr);
    bool deleteConversationFromDisk(const QString& name, QString* errOut = nullptr);

    // Network
    void sendToOpenAI(const QString& userText);

private:
    // Tabs
    QTabWidget*     m_tabs = nullptr;

    // Tab 1: Prompt
    QWidget*        m_promptTab = nullptr;
    QComboBox*      m_modelBox = nullptr;
    QComboBox*      m_convBox = nullptr;
    QLabel*         m_status = nullptr;

    QPlainTextEdit* m_responseBox = nullptr;
    QPlainTextEdit* m_questionBox = nullptr;
    QLabel*         m_hintLabel = nullptr;

    QGroupBox*      m_responseGroup = nullptr;
    QGroupBox*      m_questionGroup = nullptr;

    // Tab 2: Chat
    QTextBrowser*   m_chatView = nullptr;

    // Tab 3: Logs
    QPlainTextEdit* m_logView = nullptr;

    // Networking
    QNetworkAccessManager* m_net = nullptr;
    QNetworkReply*         m_reply = nullptr;

    // Streaming
    QByteArray m_sseBuffer;
    bool       m_inAssistant = false;
    QString    m_assistantText;

    // Conversation chain state (Responses API)
    QString    m_lastResponseId;
    QString    m_pendingResponseId;

    // Local transcript
    QVector<ChatLine> m_chatLines;

    QString    m_currentConversationName;
    bool       m_suppressConvChange = false;
};
