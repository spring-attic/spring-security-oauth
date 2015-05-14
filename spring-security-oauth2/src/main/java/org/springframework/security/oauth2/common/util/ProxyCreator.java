/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.springframework.security.oauth2.common.util;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.springframework.beans.factory.ObjectFactory;

/**
 * @author Dave Syer
 *
 */
public class ProxyCreator {

	@SuppressWarnings("unchecked")
	public static <T> T getProxy(Class<T> type, ObjectFactory<T> factory) {
		return (T) Proxy.newProxyInstance(ProxyCreator.class.getClassLoader(), new Class<?>[] { type },
				new LazyInvocationHandler<T>(factory));
	}

	private static class LazyInvocationHandler<T> implements InvocationHandler {

		private T target;

		private ObjectFactory<T> factory;

		public LazyInvocationHandler(ObjectFactory<T> factory) {
			this.factory = factory;
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			// Invocation on interface coming in...

			if (method.getName().equals("equals")) {
				return (proxy == args[0]);
			}
			else if (method.getName().equals("hashCode")) {
				return System.identityHashCode(proxy);
			}
			try {
				return method.invoke(getTarget(method), args);
			}
			catch (InvocationTargetException ex) {
				throw ex.getTargetException();
			}
		}

		private Object getTarget(Method method) {
			if (target == null) {
				target = factory.getObject();
			}
			return target;
		}

	}
}
