/*
 * Copyright 2014-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sivam.cosmosdb;

import org.crypto.util.CryptoUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;


@Configuration
@EnableConfigurationProperties(DocDbEncryKeyMetaProperties.class)
@PropertySource("classpath:keymetadata.properties")
public class DocKeyMetaConfiguration {

    @Autowired
    private DocDbEncryKeyMetaProperties properties;
    private final String masterKey = "M@st3rPassw0rd!0";
    private String emailKey;
    private String nameKey;

    private String getDecryptedEmailKey() {
        if (emailKey == null)
            emailKey = CryptoUtil.decryptID(masterKey, this.properties.getEmailkey());
        return emailKey;
    }

    private String getDecryptedNameKey() {
        if(nameKey == null)
            nameKey = CryptoUtil.decryptID(masterKey, this.properties.getNamekey());
        return nameKey;
    }

    public String encryptEmail(String email) {
        return CryptoUtil.encryptID(masterKey, getDecryptedEmailKey());
    }

    public String encryptName(String email) {
        return CryptoUtil.encryptID(masterKey, getDecryptedNameKey());
    }

    public String decryptEmail(String email) {
        return CryptoUtil.decryptID(masterKey, getDecryptedEmailKey());
    }

    public String decryptName(String email) {
        return CryptoUtil.decryptID(masterKey, getDecryptedNameKey());
    }

}
