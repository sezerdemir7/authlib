package com.inonu.authlib.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

import java.util.List;

public class ListStringSerializer implements RedisSerializer<List<String>> {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public byte[] serialize(List<String> list) throws SerializationException {
        try {
            return objectMapper.writeValueAsBytes(list);
        } catch (Exception e) {
            throw new SerializationException("List<String> serileştirilirken hata oluştu", e);
        }
    }

    @Override
    public List<String> deserialize(byte[] bytes) throws SerializationException {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return objectMapper.readValue(bytes, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            throw new SerializationException("List<String> deserialize edilirken hata oluştu", e);
        }
    }
}