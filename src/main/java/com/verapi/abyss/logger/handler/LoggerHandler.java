package com.verapi.abyss.logger.handler;

import com.verapi.abyss.logger.handler.impl.LoggerHandlerImpl;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

public interface LoggerHandler extends Handler<RoutingContext> {

    /**
     * Create a handler with default settings
     *
     * @return the handler
     */
    static LoggerHandler create() {
        return new LoggerHandlerImpl();
    }

    /**
     * Create a handler with default settings
     *
     * @param immediate  true if logging should occur as soon as request arrives
     * @return the handler
     */
    static LoggerHandler create(boolean immediate) {
        return new LoggerHandlerImpl(immediate);
    }

}
