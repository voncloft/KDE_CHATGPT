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
class QListWidget;

class QNetworkAccessManager;
class QNetworkReply;

struct ChatLine {
    QString who;   // system | you | assistant
    QString text;
    QString ts;
};

enum class AttachKind {
    Text,
    Image
};

struct Attachment {
    AttachKind kind = AttachKind::Text;
    QString path;
    QString displayName;
    QString mime;
    qint64 bytes = 0;

    QString text;        // for text attachments
    QString imageBase64; // for image attachments (raw base64, no prefix)
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
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
    void onAttachFiles();
    void onClearAttachments();

private:
    // UI helpers
    void setStatus(const QString& text);
    void appendChatMessage(const QString& who, const QString& text);
    void rebuildChatViewFromMemory();
    void logMessage(const QString& text);
    void refreshConversationDropdown();
    void refreshAttachmentListUI();

    // Streaming display
    void startAssistantMessage();
    void appendAssistantDelta(const QString& delta);
    void setAssistantFullText(const QString& text);
    void finalizeAssistantMessage();

    // API key
    QString apiKeyPath() const;
    QString loadApiKeyFromDisk() const;
    bool saveApiKeyToDisk(const QString& key, QString* errOut = nullptr);
    QString getApiKeyOrEmpty() const;

    // Conversation storage
    QString convRootDir() const;
    QString sanitizeConvName(const QString& name) const;
    QString convFilePathForName(const QString& name) const;
    void ensureConvDirs();
    bool saveConversationToDisk(const QString& name, QString* errOut = nullptr);
    bool loadConversationFromDisk(const QString& name, QString* errOut = nullptr);
    bool deleteConversationFromDisk(const QString& name, QString* errOut = nullptr);

    // Attachments
    bool addAttachmentFromPath(const QString& path, QString* errOut = nullptr);
    bool addTextAttachment(const QString& path, QString* errOut);
    bool addImageAttachment(const QString& path, QString* errOut);

    // Network
    void sendToOpenAI(const QString& userText);

private:
    // Tabs
    QTabWidget*     m_tabs = nullptr;

    // Prompt tab
    QWidget*        m_promptTab = nullptr;
    QComboBox*      m_modelBox = nullptr;
    QComboBox*      m_convBox = nullptr;
    QLabel*         m_status = nullptr;

    QPlainTextEdit* m_responseBox = nullptr;
    QPlainTextEdit* m_questionBox = nullptr;
    QLabel*         m_hintLabel = nullptr;
    QListWidget*    m_attachList = nullptr;

    QGroupBox*      m_responseGroup = nullptr;
    QGroupBox*      m_questionGroup = nullptr;

    // Chat tab
    QTextBrowser*   m_chatView = nullptr;

    // Logs tab
    QPlainTextEdit* m_logView = nullptr;

    // Networking
    QNetworkAccessManager* m_net = nullptr;
    QNetworkReply*         m_reply = nullptr;

    // SSE + raw capture
    QByteArray m_sseBuffer;
    QByteArray m_rawAll;     // capture everything from reply (for debugging 400s)

    bool       m_inAssistant = false;
    QString    m_assistantText;

    // Responses API chaining
    QString    m_lastResponseId;
    QString    m_pendingResponseId;

    // Transcript + saved conversations
    QVector<ChatLine> m_chatLines;
    QString           m_currentConversationName;
    bool              m_suppressConvChange = false;

    // Attachments
    QVector<Attachment> m_attachments;

private:
    static constexpr int    MAX_TEXT_CHARS = 200000;
    static constexpr qint64 MAX_TOTAL_ATTACH_BYTES = 12LL * 1024LL * 1024LL; // 12MB safety
};
