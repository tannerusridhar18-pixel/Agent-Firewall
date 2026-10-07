package io.intentguard.gateway.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ArgumentHasherTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void equivalentJsonWithDifferentKeyOrderProducesIdenticalHash() throws Exception {
        var json1 = mapper.readTree("{\"target\":\"workspace/a.txt\",\"mode\":\"read\",\"options\":{\"strict\":true,\"depth\":2}}");
        var json2 = mapper.readTree("{\"options\":{\"depth\":2,\"strict\":true},\"mode\":\"read\",\"target\":\"workspace/a.txt\"}");

        String hash1 = ArgumentHasher.canonicalHash(json1);
        String hash2 = ArgumentHasher.canonicalHash(json2);

        assertNotNull(hash1);
        assertEquals(64, hash1.length());
        assertEquals(hash1, hash2);
    }

    @Test
    void differentJsonProducesDifferentHash() throws Exception {
        var json1 = mapper.readTree("{\"target\":\"workspace/a.txt\"}");
        var json2 = mapper.readTree("{\"target\":\"workspace/b.txt\"}");

        String hash1 = ArgumentHasher.canonicalHash(json1);
        String hash2 = ArgumentHasher.canonicalHash(json2);

        assertNotEquals(hash1, hash2);
    }

    @Test
    void nullAndEmptyJsonProduceDeterministicHash() {
        String hashNull = ArgumentHasher.canonicalHash(null);
        assertNotNull(hashNull);
        assertEquals(64, hashNull.length());
    }
}
