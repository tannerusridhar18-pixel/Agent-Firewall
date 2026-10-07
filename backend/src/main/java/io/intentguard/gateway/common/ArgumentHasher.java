package io.intentguard.gateway.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;

public final class ArgumentHasher {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ArgumentHasher() {}

    public static String canonicalHash(JsonNode arguments) {
        try {
            JsonNode canonicalNode = canonicalize(arguments);
            String canonicalJson = MAPPER.writeValueAsString(canonicalNode);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to calculate canonical argument hash", e);
        }
    }

    public static JsonNode canonicalize(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return MAPPER.createObjectNode();
        }
        if (node.isObject()) {
            ObjectNode sortedObject = MAPPER.createObjectNode();
            List<String> fieldNames = new ArrayList<>();
            Iterator<String> it = node.fieldNames();
            while (it.hasNext()) {
                fieldNames.add(it.next());
            }
            Collections.sort(fieldNames);
            for (String fieldName : fieldNames) {
                sortedObject.set(fieldName, canonicalize(node.get(fieldName)));
            }
            return sortedObject;
        }
        if (node.isArray()) {
            ArrayNode canonicalArray = MAPPER.createArrayNode();
            for (JsonNode element : node) {
                canonicalArray.add(canonicalize(element));
            }
            return canonicalArray;
        }
        return node;
    }
}
