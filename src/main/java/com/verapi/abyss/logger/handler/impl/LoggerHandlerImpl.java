package com.verapi.abyss.logger.handler.impl;

import com.verapi.abyss.common.Config;
import com.verapi.abyss.common.Constants;
import com.verapi.abyss.common.message.ApiTraffic;
import com.verapi.abyss.logger.handler.LoggerHandler;
import io.vertx.core.MultiMap;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public class LoggerHandlerImpl implements LoggerHandler {

    private static Logger logger = LoggerFactory.getLogger(LoggerHandlerImpl.class);

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
        UUID uuid = UUID.randomUUID();
        String remoteClient = getClientAddress(routingContext.request().remoteAddress());
        HttpMethod method = routingContext.request().method();
        String session = routingContext.session() != null ? routingContext.session().id() : "";
        String scheme = routingContext.request().scheme();
        String uri = routingContext.request().uri();
        String path = routingContext.request().path();
        String query = routingContext.request().query();
        HttpVersion version = routingContext.request().version();
        Boolean isSSL = routingContext.request().isSSL();
        String localHost = routingContext.request().host().contains(":")
                ? routingContext.request().host().substring(0, routingContext.request().host().indexOf(":"))
                : routingContext.request().host();
        int localPort = routingContext.request().localAddress().port();
        int statusCode = routingContext.response().getStatusCode();
        //String username = routingContext.user() != null ? routingContext.user().principal().getString("username") : "";
        String username = (routingContext.session() != null && routingContext.session().get(Constants.AUTH_ABYSS_PORTAL_USER_NAME_SESSION_VARIABLE_NAME) != null)
                ? routingContext.session().get(Constants.AUTH_ABYSS_PORTAL_USER_NAME_SESSION_VARIABLE_NAME) : "";

        JsonObject message = new JsonObject()
                .put(ApiTraffic.ID, uuid.toString())
                .put(ApiTraffic.HTTP_METHOD, method)
                .put(ApiTraffic.HTTP_SESSION, session)
                .put(ApiTraffic.HTTP_VERSION, version)
                .put(ApiTraffic.REMOTE_CLIENT, remoteClient)
                .put(ApiTraffic.REQUEST_HOST, localHost)
                .put(ApiTraffic.REQUEST_IS_SSL, isSSL)
                .put(ApiTraffic.REQUEST_PATH, path)
                .put(ApiTraffic.REQUEST_PORT, localPort)
                .put(ApiTraffic.REQUEST_QUERY, query)
                .put(ApiTraffic.REQUEST_SCHEME, scheme)
                .put(ApiTraffic.REQUEST_URI, uri)
                .put(ApiTraffic.RESPONSE_BODY, "") //TODO: put response body
                .put(ApiTraffic.RESPONSE_STATUS_CODE, statusCode)
                .put(ApiTraffic.TIMESTAMP, Instant.now())
                .put(ApiTraffic.USERNAME, username);

        if (immediate)
            log(routingContext, message);
        else
            routingContext.addBodyEndHandler(event1 -> log(routingContext, message));

        routingContext.next();
    }

    private void log(RoutingContext routingContext, JsonObject message) {
        logger.trace("Abyss LoggerHandler>>{}", packMessage(routingContext, message).encodePrettily());

        DeliveryOptions deliveryOptions = new DeliveryOptions()
                .setSendTimeout(Config.getInstance().getConfigJsonObject().getInteger(Constants.EVENTBUS_ADDRESS_API_TRAFFIC_LOG_SEND_TIMEOUT));
        routingContext.vertx().eventBus().<JsonObject>send(Constants.EVENTBUS_ADDRESS_API_TRAFFIC_LOG, packMessage(routingContext, message), deliveryOptions, event -> {
            if (event.succeeded())
                logger.trace("successfully send to {}, response:{}", Constants.EVENTBUS_ADDRESS_API_TRAFFIC_LOG, event.result().body().toString());
            else
                logger.error("unable to send to {}, error:{}", Constants.EVENTBUS_ADDRESS_API_TRAFFIC_LOG, event.cause().getLocalizedMessage());
        });
    }

    private JsonObject packMessage(RoutingContext routingContext, JsonObject message) {
        long contentLength = 0;
        if (immediate) {
            Object obj = routingContext.request().headers().get(HttpHeaders.CONTENT_LENGTH);
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
        final MultiMap requestHeaders = routingContext.request().headers();
        final MultiMap responseHeaders = routingContext.response().headers();
        String referer = requestHeaders.contains(HttpHeaders.REFERER) ? requestHeaders.get(HttpHeaders.REFERER) : "";
        String userAgent = requestHeaders.get(HttpHeaders.USER_AGENT);
        String acceptEncoding = requestHeaders.get(HttpHeaders.ACCEPT_ENCODING);
        String contentType = responseHeaders.get(HttpHeaders.CONTENT_TYPE);
        long bytesRead = routingContext.request().bytesRead();
        long bytesSent = routingContext.response().bytesWritten();


        return message
                .put(ApiTraffic.ACCEPT_ENCODING, acceptEncoding)
                .put(ApiTraffic.CONTENT_LENGTH, contentLength)
                .put(ApiTraffic.CONTENT_TYPE, contentType)
                .put(ApiTraffic.COOKIES, extractCookies(routingContext.cookies()))
                .put(ApiTraffic.REFERER, referer)
                .put(ApiTraffic.REQUEST_HEADERS, extractHeaders(routingContext.request().headers()))
                .put(ApiTraffic.REQUEST_PARAMS, extractParams(routingContext.request().params()))
                .put(ApiTraffic.RESPONSE_HEADERS, extractHeaders(routingContext.response().headers()))
                .put(ApiTraffic.USER_AGENT, userAgent)
                .put(ApiTraffic.REQUEST_BYTES_READ, bytesRead)
                .put(ApiTraffic.RESPONSE_BYTES_WRITTEN, bytesSent)
                .put(ApiTraffic.REQUEST_BODY, routingContext.getBodyAsString());
    }


    private String getClientAddress(SocketAddress inetSocketAddress) {
        if (inetSocketAddress == null) {
            return null;
        }

        return inetSocketAddress.host();
    }

    private JsonObject extractHeaders(final MultiMap headersMap) {

        JsonObject headers = new JsonObject();
        headersMap.forEach(entry -> {
            headers.put(entry.getKey(), entry.getValue());
        });

        return headers;
    }

    private JsonObject extractParams(final MultiMap paramsMap) {

        JsonObject params = new JsonObject();
        paramsMap.forEach(entry -> {
            params.put(entry.getKey(), entry.getValue());
        });

        return params;
    }

    private JsonArray extractCookies(final Set<Cookie> cookies) {

        JsonArray cookiesJsonArray = new JsonArray();
        for (final Cookie cookie : cookies) {
            cookiesJsonArray.add(new JsonObject().put("name", cookie.getName()).put("value", cookie.getValue()));
        }

        return cookiesJsonArray;
    }

}
