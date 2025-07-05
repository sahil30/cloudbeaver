/*
 * DBeaver - Universal Database Manager
 * Copyright (C) 2010-2020 DBeaver Corp and others
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
package io.cloudbeaver.auth.provider.ldap;

import io.cloudbeaver.DBWAuthProvider;
import io.cloudbeaver.model.session.WebSession;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import io.cloudbeaver.registry.WebAuthProviderPropertyEncryption;
import org.jkiss.dbeaver.DBException;
import org.jkiss.utils.CommonUtils;
import java.util.Hashtable;

import java.util.Map;

/**
 * Auth provider
 */
/**
 * Simple LDAP authentication provider.
 */
public class LdapAuthProvider implements DBWAuthProvider<LdapAuthSession> {

    public static final String PROVIDER_ID = "ldap";
    public static final String CRED_USER = "user";
    public static final String CRED_PASSWORD = "password";
    public static final String CFG_URL = "url";
    public static final String CFG_BASE_DN = "baseDn";
    public static final String CFG_USER_DN_PATTERN = "userDnPattern";

    @Override
    public LdapAuthSession openSession(WebSession mainSession, Map<String, Object> providerConfig, Map<String, Object> userCredentials, Map<String, Object> authParameters) throws DBException {
        String url = CommonUtils.toString(providerConfig.get(CFG_URL), null);
        String baseDn = CommonUtils.toString(providerConfig.get(CFG_BASE_DN), null);
        String userDnPattern = CommonUtils.toString(providerConfig.get(CFG_USER_DN_PATTERN), null);

        String userName = CommonUtils.toString(authParameters.get(CRED_USER), null);
        String password = CommonUtils.toString(authParameters.get(CRED_PASSWORD), null);

        if (CommonUtils.isEmpty(url) || CommonUtils.isEmpty(userName) || CommonUtils.isEmpty(password)) {
            throw new DBException("Missing LDAP configuration or credentials");
        }

        String userDn;
        if (!CommonUtils.isEmpty(userDnPattern)) {
            userDn = userDnPattern.replace("{user}", userName);
        } else if (!CommonUtils.isEmpty(baseDn)) {
            userDn = "uid=" + userName + "," + baseDn;
        } else {
            throw new DBException("User DN pattern or base DN must be provided");
        }

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        try {
            DirContext ctx = new InitialDirContext(env);
            ctx.close();
        } catch (NamingException e) {
            throw new DBException("LDAP authentication failed", e);
        }
        return new LdapAuthSession(mainSession, userName);
    }

    @Override
    public void closeSession(LdapAuthSession localAuthSession) throws DBException {

    }

    @Override
    public void refreshSession(LdapAuthSession localAuthSession) throws DBException {

    }

    public static String makeClientPasswordHash(String userName, String password) {
        return WebAuthProviderPropertyEncryption.hash.encrypt(userName, password);
    }

}
