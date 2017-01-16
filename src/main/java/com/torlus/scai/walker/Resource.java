package com.torlus.scai.walker;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Resource {	
	public String id;

	public List<String> validate(boolean create) {
		return null;
	}

	public static class OfType<T extends Resource> {
		private ArrayList<T> all = new ArrayList<>();
		private String file;

		public final List<T> all() {
			return all;
		}

		public final T create(T obj) {
			if (obj.id != null)
				throw new RuntimeException("create(): unexpected id");
			List<String> validationErrors = obj.validate(true);
			if (validationErrors != null && validationErrors.size() > 0)
				throw new RuntimeException("create(): validation error(s)");
			obj.id = UUID.randomUUID().toString();
			all.add(obj);
			return obj;
		}

		public final T find(String id) {
			for (T obj : all) {
				if (obj.id.equals(id))
					return obj;
			}
			return null;
		}

		public final T replace(String id, T obj) {
			T old = find(id);
			if (old == null)
				return null;
			if (!old.id.equals(obj.id))
				throw new RuntimeException("replace(): unexpected id");
			List<String> validationErrors = obj.validate(false);
			if (validationErrors != null && validationErrors.size() > 0)
				throw new RuntimeException("replace(): validation error(s)");
			all.set(all.indexOf(old), obj);
			return obj;
		}

		public final T delete(String id) {
			int index = -1;
			for (int n = 0; n < all.size(); n++) {
				if (id.equals(all.get(n).id)) {
					index = n;
					break;
				}
			}
			if (index < 0)
				return null;
			return all.remove(index);
		}
		
		public final void save(String file) throws Exception {
			ObjectMapper om = new ObjectMapper();
			om.writeValue(new File(file), all);
		}
		
		public final void save() throws Exception {
			save(this.file);
		}
		
		@SuppressWarnings("unchecked")
		public final void load(String file, Class<T> type) throws Exception {
			this.file = file;
			ObjectMapper om = new ObjectMapper();
			ArrayList tmp = om.readValue(Files.readAllBytes(Paths.get(file)), ArrayList.class);
			all.clear();
			for(Object o: tmp) {
				byte[] val = om.writeValueAsBytes(o);
				all.add(om.readValue(val, type));
				
			}
		}
	}

}
