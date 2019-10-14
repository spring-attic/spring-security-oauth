package org.springframework.security.oauth2.common.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.io.ObjectStreamClass;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.springframework.util.ClassUtils;

public class SerializationUtils {

	/**
	 * A list of classes which are allowed to deserialize.
	 */
	private static final List<String> ALLOWED_CLASSES;

	static {
		List<String> classes = new ArrayList<String>();
		classes.add("java.lang.");
		classes.add("java.util.");
		classes.add("org.springframework.security.");
		ALLOWED_CLASSES = Collections.unmodifiableList(classes);
	}

	public static byte[] serialize(Object state) {
		ObjectOutputStream oos = null;
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream(512);
			oos = new ObjectOutputStream(bos);
			oos.writeObject(state);
			oos.flush();
			return bos.toByteArray();
		}
		catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
		finally {
			if (oos != null) {
				try {
					oos.close();
				}
				catch (IOException e) {
					// eat it
				}
			}
		}
	}

	public static <T> T deserialize(byte[] byteArray) {
		ObjectInputStream oip = null;
		try {
			oip = new SaferObjectInputStream(new ByteArrayInputStream(byteArray),
					Thread.currentThread().getContextClassLoader(), ALLOWED_CLASSES);
			@SuppressWarnings("unchecked")
			T result = (T) oip.readObject();
			return result;
		}
		catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
		catch (ClassNotFoundException e) {
			throw new IllegalArgumentException(e);
		}
		finally {
			if (oip != null) {
				try {
					oip.close();
				}
				catch (IOException e) {
					// eat it
				}
			}
		}
	}

	/**
	 * Special ObjectInputStream subclass that checks if classes are allowed to deserialize.
	 * The class should be configured with a whitelist of only allowed (safe) classes to deserialize.
	 *
	 * @author Artem Smotrakov
	 */
	private static class SaferObjectInputStream extends ObjectInputStream {

		/**
		 * The whitelist of classes which are allowed for deserialization.
		 */
		private final List<String> allowedClasses;

		/**
		 * The class loader to use for loading local classes.
		 */
		private final ClassLoader classLoader;

		/**
		 * Create a new SaferObjectInputStream for the given InputStream, class loader and  allowed class names.
		 *
		 * @param in             the InputStream to read from
		 * @param classLoader    the ClassLoader to use for loading local classes
		 * @param allowedClasses the list of allowed classes for deserialization
		 * @throws IOException
		 */
		SaferObjectInputStream(InputStream in, ClassLoader classLoader, List<String> allowedClasses)
				throws IOException {

			super(in);
			this.classLoader = classLoader;
			this.allowedClasses = Collections.unmodifiableList(allowedClasses);
		}

		/**
		 * Resolve the class only if it's allowed to deserialize.
		 *
		 * @see ObjectInputStream#resolveClass(ObjectStreamClass)
		 */
		@Override
		protected Class<?> resolveClass(ObjectStreamClass classDesc) throws IOException, ClassNotFoundException {
			if (isProhibited(classDesc.getName())) {
				throw new NotSerializableException("Not allowed to deserialize " + classDesc.getName());
			}
			if (this.classLoader != null) {
				return ClassUtils.forName(classDesc.getName(), this.classLoader);
			}
			return super.resolveClass(classDesc);
		}

		/**
		 * Check if the class is allowed to be deserialized.
		 *
		 * @param className the class to check
		 * @return true if the class is not allowed to be deserialized, false otherwise
		 */
		private boolean isProhibited(String className) {
			for (String allowedClass : this.allowedClasses) {
				if (className.startsWith(allowedClass)) {
					return false;
				}
			}
			return true;
		}
	}

}
