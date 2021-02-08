package org.springframework.security.acls.mongodb;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import de.flapdoodle.embed.process.runtime.Network;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.mongodb.core.MongoTemplate;

import java.io.IOException;

@ComponentScan(basePackages = {"org.springframework.security.acls"})
public class TestContextConfiguration {

    @Bean
    public String database() {
        return "spring-security-acl-test";
    }

    @Bean
    public String collection() {
        return "test-collection";
    }

    @Bean
    public int port() throws IOException {
        return Network.getFreeServerPort();
    }

    @Bean
    public MongoClient mongo(int port) {
        return MongoClients.create("mongodb://localhost:"+port);
    }

    @Bean
    public MongoTemplate mongoTemplate(MongoClient mongo, String database) {
        return new MongoTemplate(mongo, database);
    }
}
