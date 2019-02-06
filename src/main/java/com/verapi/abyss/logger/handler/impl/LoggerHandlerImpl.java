package com.verapi.abyss.logger.handler.impl;

import com.verapi.abyss.logger.handler.LoggerHandler;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggerHandlerImpl implements LoggerHandler {

    private static Logger logger = LoggerFactory.getLogger(LoggerHandlerImpl.class);

    private static final String TIMESTAMP = "timestamp";
    private static final String REMOTECLIENT = "remoteclient";
    private static final String HTTPMETHOD = "httpmethod";
    private static final String URI = "uri";
    private static final String HTTPVERSION = "httpversion";
    private static final String CONTENTLENGTH = "contentlength";
    private static final String HEADERS = "headers";
    private static final String REFERRER = "referrer";
    private static final String USERAGENT = "useragent";

    private final boolean immediate;

    public LoggerHandlerImpl(boolean immediate) {
        this.immediate = immediate;
    }

    public LoggerHandlerImpl() {
        this(false);
    }

    @Override
    public void handle(RoutingContext routingContext) {
        // common logging data
        long timestamp = System.currentTimeMillis();
        String remoteClient = getClientAddress(routingContext.request().remoteAddress());
        HttpMethod method = routingContext.request().method();
        String uri = routingContext.request().uri();
        HttpVersion version = routingContext.request().version();

        JsonObject message = new JsonObject()
                .put(TIMESTAMP, timestamp)
                .put(REMOTECLIENT, remoteClient)
                .put(HTTPMETHOD, method)
                .put(URI, uri)
                .put(HTTPVERSION, version);

        if (immediate)
            log(routingContext, message);
        else
            routingContext.addBodyEndHandler(event1 -> log(routingContext, message));

        routingContext.next();
    }

    private void log(RoutingContext routingContext, JsonObject message) {
        logger.info("Abyss LoggerHandler>>{}",packMessage(routingContext, message).encodePrettily());
    }

    private JsonObject packMessage(RoutingContext routingContext, JsonObject message) {
        long contentLength = 0;
        if (immediate) {
            Object obj = routingContext.request().headers().get("content-length");
            if (obj != null) {
                try {
                    contentLength = Long.parseLong(obj.toString());
                } catch (NumberFormatException e) {
                    // ignore it and continue
                }
            }
        } else {
            contentLength = routingContext.request().response().bytesWritten();
        }
        final MultiMap headers = routingContext.request().headers();
        String referrer = headers.contains("referrer") ? headers.get("referrer") : headers.get("referer");
        String userAgent = headers.get("user-agent");
        return message
                .put(CONTENTLENGTH, contentLength)
//                .put(HEADERS, headers)
                .put(REFERRER, referrer)
                .put(USERAGENT, userAgent);

    }

    private String getClientAddress(SocketAddress inetSocketAddress) {
        if (inetSocketAddress == null) {
            return null;
        }
        return inetSocketAddress.host();
    }

}
