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
     * @param immediate true if logging should occur as soon as request arrives
     * @return the handler
     */
    static LoggerHandler create(boolean immediate) {
        return new LoggerHandlerImpl(immediate);
    }

}
