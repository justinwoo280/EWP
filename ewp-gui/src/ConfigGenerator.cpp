#include "ConfigGenerator.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include <QDebug>

// =====================================================================
// Public API
// =====================================================================

QJsonObject ConfigGenerator::generateClientConfig(const EWPNode &node,
                                                  const SettingsDialog::AppSettings &settings,
                                                  bool tunMode)
{
    QJsonObject cfg;
    cfg["inbounds"]  = generateInbounds(node, settings, tunMode);

    QJsonArray outs;
    outs.append(generateOutbound(node));
    cfg["outbounds"] = outs;

    cfg["router"] = generateRouter();
    cfg["client"] = generateClient(node);
    return cfg;
}

QString ConfigGenerator::generateConfigFile(const EWPNode &node,
                                            const SettingsDialog::AppSettings &settings,
                                            bool tunMode)
{
    QJsonDocument doc(generateClientConfig(node, settings, tunMode));
    return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
}

bool ConfigGenerator::saveConfig(const QJsonObject &config, const QString &filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Failed to open config file for writing:" << filePath;
        return false;
    }
    QJsonDocument doc(config);
    f.write(doc.toJson(QJsonDocument::Indented));
    f.close();
    return true;
}

// =====================================================================
// Inbound (TUN or SOCKS5)
// =====================================================================

QJsonArray ConfigGenerator::generateInbounds(const EWPNode &node,
                                              const SettingsDialog::AppSettings &settings,
                                              bool tunMode)
{
    QJsonArray arr;
    QJsonObject in;
    if (tunMode) {
        in["tag"]  = "tun-in";
        in["type"] = "tun";
        // v2 cfg.InboundCfg nests TUN-specific settings under a
        // 'tun:' sub-object — flat layout makes the loader reject
        // with 'tun.address is required' even when address is set.
        QJsonObject tun;
        tun["address"] = settings.tunIP;          // e.g. "10.233.0.2/24"
        QJsonArray dns;
        if (!settings.tunnelDNS.isEmpty())   dns.append(settings.tunnelDNS);
        if (!settings.tunnelDNSv6.isEmpty()) dns.append(settings.tunnelDNSv6);
        if (!dns.isEmpty()) tun["dns"] = dns;
        tun["mtu"]      = settings.tunMTU;
        tun["fake_ip"]  = true;
        // No bypass_server emission anymore: sing-tun's
        // DefaultInterfaceMonitor watches kernel routing in real
        // time and dialer Control funcs always bind to the current
        // physical egress NIC, so no startup-time hint is needed.
        in["tun"] = tun;
    } else {
        in["tag"]    = "local-socks";
        in["type"]   = "socks5";
        in["listen"] = settings.listenAddr;       // e.g. "127.0.0.1:1080"
    }
    arr.append(in);
    return arr;
}

// =====================================================================
// Outbound (always ewpclient in v2)
// =====================================================================

QJsonObject ConfigGenerator::generateOutbound(const EWPNode &node)
{
    QJsonObject out;
    out["tag"]  = "proxy-out";
    out["type"] = "ewpclient";
    out["uuid"] = node.uuid;
    out["transport"] = generateTransport(node);
    return out;
}

QJsonObject ConfigGenerator::generateTransport(const EWPNode &node)
{
    QJsonObject t;
    const char *kind = "websocket";
    QString path     = node.wsPath;
    QString scheme   = "wss";
    switch (node.transportMode) {
        case EWPNode::WS:     kind = "websocket"; path = node.wsPath;          scheme = "wss";   break;
        case EWPNode::GRPC:   kind = "grpc";      path = node.grpcServiceName; scheme = "grpcs"; break;
        case EWPNode::XHTTP:  kind = "xhttp";     path = node.xhttpPath;       scheme = "https"; break;
        case EWPNode::H3GRPC: kind = "h3grpc";    path = node.grpcServiceName; scheme = "h3";    break;
    }

    t["kind"] = QString::fromUtf8(kind);

    // url field as understood by cmd/ewp/cfg/build.go::splitURL
    QString hostForURL = node.host.isEmpty() ? node.server : node.host;
    QString url = QString("%1://%2:%3%4")
                      .arg(scheme)
                      .arg(hostForURL)
                      .arg(node.serverPort)
                      .arg(path.startsWith('/') || kind == QStringLiteral("grpc") || kind == QStringLiteral("h3grpc")
                               ? path
                               : "/" + path);
    t["url"] = url;

    if (!node.host.isEmpty()) t["host"] = node.host;
    QString sni = node.effectiveSNI();
    if (!sni.isEmpty())       t["sni"]  = sni;

    t["ech"] = node.enableECH;
    if (node.enableECH && !node.echDomain.isEmpty()) {
        // Only emit when non-empty: an empty echDomain means
        // "infer from sni / url" and the cmd/ewp side already
        // implements that priority chain. Emitting empty would
        // make the yaml noisier without changing behaviour.
        t["ech_domain"] = node.echDomain;
    }
    return t;
}

// =====================================================================
// Router (single default outbound — v2 has no rule engine yet)
// =====================================================================

QJsonObject ConfigGenerator::generateRouter()
{
    QJsonObject r;
    r["default"] = "proxy-out";
    return r;
}

// =====================================================================
// Client (umbrella DoH list — used by ECH bootstrap + server name DNS)
// =====================================================================

QJsonObject ConfigGenerator::generateClient(const EWPNode &node)
{
    QJsonObject client;
    if (!node.dohServers.isEmpty()) {
        QJsonObject doh;
        QJsonArray servers;
        for (const QString &s : node.dohServers.split(',', Qt::SkipEmptyParts)) {
            QString trimmed = s.trimmed();
            if (!trimmed.isEmpty()) servers.append(trimmed);
        }
        doh["servers"] = servers;
        client["doh"]  = doh;
    }
    // Empty client.doh -> cmd/ewp falls back to its built-in default
    // (AliDNS + DNSPod + doh.pub), so the GUI does not have to bake
    // that list in itself.
    return client;
}
