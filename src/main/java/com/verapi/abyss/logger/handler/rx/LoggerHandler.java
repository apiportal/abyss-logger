/*
 * Copyright 2019 Verapi Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.verapi.abyss.logger.handler.rx;

import io.vertx.core.Handler;
import io.vertx.reactivex.ext.web.RoutingContext;
import io.vertx.lang.rx.TypeArg;

public class LoggerHandler implements Handler<RoutingContext> {

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LoggerHandler that = (LoggerHandler) o;
        return delegate.equals(that.delegate);
    }

    @Override
    public int hashCode() {
        return delegate.hashCode();
    }

    public static final TypeArg<LoggerHandler> __TYPE_ARG = new TypeArg<>(
            obj -> new LoggerHandler((com.verapi.abyss.logger.handler.LoggerHandler) obj),
            LoggerHandler::getDelegate
    );

    private final com.verapi.abyss.logger.handler.LoggerHandler delegate;

    private LoggerHandler(com.verapi.abyss.logger.handler.LoggerHandler delegate) {
        this.delegate = delegate;
    }

    private com.verapi.abyss.logger.handler.LoggerHandler getDelegate() {
        return delegate;
    }

    public void handle(RoutingContext arg0) {
        delegate.handle(arg0.getDelegate());
    }

    /**
     * Create a handler with default settings
     *
     * @return the handler
     */
    public static LoggerHandler create() {
        return LoggerHandler.newInstance(com.verapi.abyss.logger.handler.LoggerHandler.create());
    }

    /**
     * Create a handler with default settings
     *
     * @param immediate true if logging should occur as soon as request arrives
     * @return the handler
     */
    public static LoggerHandler create(boolean immediate) {
        return LoggerHandler.newInstance(com.verapi.abyss.logger.handler.LoggerHandler.create(immediate));
    }

    private static LoggerHandler newInstance(com.verapi.abyss.logger.handler.LoggerHandler arg) {
        return arg != null ? new LoggerHandler(arg) : null;
    }

}
