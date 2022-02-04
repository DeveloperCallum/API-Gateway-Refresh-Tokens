package com.beamedcallum.gateway.authorization.refresh;

import com.beamedcallum.gateway.authorization.refresh.exceptions.TokenGenerationException;
import com.beamedcallum.gateway.tokens.SelfContainedToken;
import com.beamedcallum.gateway.tokens.TokenService;
import com.beamedcallum.gateway.tokens.TokenServiceAuth;
import com.beamedcallum.gateway.tokens.exceptions.TokenExpiredException;
import com.beamedcallum.gateway.tokens.exceptions.TokenRuntimeException;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * A refresh token is exchanged for a new access token and new refresh token provided conditions are met.
 *
 * @param <K> The refresh token
 * @param <V> The authorisation token
 */
public abstract class RefreshTokenService<K extends SelfContainedToken<?>, V extends SelfContainedToken<?>> extends TokenService<K, RefreshTokenService.RefreshRunnable> {
    private final Map<Integer, ServiceData> dataMap = new HashMap<>();

    @Deprecated
    public void authoriseToken(int id, K refresh, V auth) {
        authoriseToken(new RefreshRunnable(id, refresh, auth));
    }

    @Deprecated
    public void authoriseToken(K refresh, V auth) {
        authoriseToken(new RefreshRunnable(refresh, auth));
    }

    public void invalidateToken(int id){
        invalidateToken(new RefreshRunnable(id));
    }

    public RefreshTokenData<K, V> create() {
        ServiceData newNode = new ServiceData();

        K refresh = generateRefreshToken();
        V auth = generateAuthToken();

        newNode.refreshToken = refresh;
        newNode.authToken = auth;

        return newNode;
    }

    /**
     * Refresh the token authorisation
     * @param refreshToken The token that was given for refreshing
     * @return The new tokens
     */
    public abstract RefreshTokenData<K, V> generateChildAuth(K refreshToken) throws TokenGenerationException, TokenExpiredException;

    protected abstract V generateAuthToken();

    protected abstract K generateRefreshToken();

    protected abstract boolean isAuthValid(V auth) throws TokenExpiredException;

    protected abstract boolean isRefreshValid(K refresh) throws TokenExpiredException;

    protected boolean tokenExists(int id, SelfContainedToken<?> token, TOKEN_TYPE token_type) {
        if (!dataMap.containsKey(id)) {
            return false;
        }

        RefreshTokenData<K, V> returnedToken = dataMap.get(id).search(token, token_type);

        return returnedToken != null;
    }


    public boolean isCurrentGeneration(SelfContainedToken<?> token, TOKEN_TYPE token_type){
        int id = Integer.parseInt(token.getClaim("id"));

        return isCurrentGeneration(id, token, token_type);
    }

    protected boolean isCurrentGeneration(int id, SelfContainedToken<?> token, TOKEN_TYPE token_type) {
        if (!dataMap.containsKey(id)){
            throw new TokenRuntimeException("token ID not valid");
        }

        ServiceData firstNode = dataMap.get(id);
        ServiceData current = firstNode.getLast();

        if (token_type == TOKEN_TYPE.AUTHORISATION_TOKEN){
            return token.equals(current.getAuthToken());
        }

        if (token_type == TOKEN_TYPE.REFRESH_TOKEN){
            return token.equals(current.getRefreshToken());
        }

        throw new RuntimeException("Should not have reached this");
    }

    @Deprecated
    protected RefreshTokenData<K, V> add(V authToken, K refreshToken) {
        int id = generateID();

        ServiceData newNode = new ServiceData();
        newNode.authToken = authToken;
        newNode.refreshToken = refreshToken;

        dataMap.put(id, newNode);

        return newNode;
    }

    protected RefreshTokenData<K, V> addChild(int id, K refreshToken, V authToken) {
        if (!dataMap.containsKey(id)) {
            throw  new RuntimeException("ID does not exist");
        }

        ServiceData firstNode = dataMap.get(id);
        ServiceData lastNode = firstNode.getLast();

        ServiceData newNode = new ServiceData();
        newNode.authToken = authToken;
        newNode.refreshToken = refreshToken;

        lastNode.nextNode = newNode;

        return newNode;
    }

    protected RefreshTokenData<K, V> add(int id, K refreshToken, V authToken) {
        if (!dataMap.containsKey(id)) {
            ServiceData newNode = new ServiceData();
            newNode.authToken = authToken;
            newNode.refreshToken = refreshToken;

            dataMap.put(id, newNode);
            return newNode;
        }

        ServiceData firstNode = dataMap.get(id);
        ServiceData lastNode = firstNode.getLast();

        ServiceData newNode = new ServiceData();
        newNode.authToken = authToken;
        newNode.refreshToken = refreshToken;

        lastNode.nextNode = newNode;

        return newNode;
    }

    protected int generateID() {
        SecureRandom secureRandom = new SecureRandom();
        int possibleID = secureRandom.nextInt(Integer.MAX_VALUE);

        if (!dataMap.containsKey(possibleID)) {
            return possibleID;
        }

        return generateID();
    }

    public abstract void invalidateToken(SelfContainedToken<?> token);

    protected class RefreshRunnable implements TokenServiceAuth {
        private int id = -1;
        private V authToken;
        private K refreshToken;
        private RefreshTokenData<K, V> data;

        public RefreshRunnable(int id) {
            this.id = id;
        }

        public RefreshRunnable(int id, K refreshToken, V authToken) {
            this.id = id;
            this.authToken = authToken;
            this.refreshToken = refreshToken;
        }

        public RefreshRunnable(K refreshToken, V authToken) {
            this.authToken = authToken;
            this.refreshToken = refreshToken;
        }

        @Override
        public void authoriseToken() {
            if (containsKey(id)) {
                data = add(authToken, refreshToken);
                return;
            }

            data = add(id, refreshToken, authToken);
        }

        @Override
        public void invalidateToken() {
            remove(id);
        }

        protected RefreshTokenData<K, V> getData() {
            return data;
        }

        protected boolean isEmpty() {
            return dataMap.isEmpty();
        }

        protected boolean containsKey(Object key) {
            return dataMap.containsKey(key);
        }

        protected ServiceData get(Object key) {
            return dataMap.get(key);
        }

        protected ServiceData put(Integer key, ServiceData value) {
            return dataMap.put(key, value);
        }

        protected void remove(Object key) {
            dataMap.remove(key);
        }

        protected int getId() {
            return id;
        }

        protected void setId(int id) {
            this.id = id;
        }

        protected V getAuthToken() {
            return authToken;
        }

        protected K getRefreshToken() {
            return refreshToken;
        }

        protected void setData(RefreshTokenData<K, V> data) {
            this.data = data;
        }
    }

    private class ServiceData implements RefreshTokenData<K, V> {
        private K refreshToken;
        private V authToken;
        private ServiceData nextNode = null;

        public ServiceData getLast() {
            if (nextNode == null) {
                return this;
            }

            return nextNode.getLast();
        }

        @Override
        public K getRefreshToken() {
            return refreshToken;
        }

        @Override
        public V getAuthToken() {
            return authToken;
        }

        @Override
        public RefreshTokenData<K, V> getNext() {
            return nextNode;
        }

        public RefreshTokenData<K, V> search(SelfContainedToken<?> token) {
            if (this.authToken.equals(token)) {
                return this;
            }

            if (this.refreshToken.equals(token)) {
                return this;
            }

            if (nextNode == null) {
                return null;
            }

            return search(token);
        }

        public RefreshTokenData<K, V> search(SelfContainedToken<?> token, TOKEN_TYPE token_type) {
            if (this.authToken.equals(token) && token_type == TOKEN_TYPE.AUTHORISATION_TOKEN) {
                return this;
            }

            if (this.refreshToken.equals(token) && token_type == TOKEN_TYPE.REFRESH_TOKEN) {
                return this;
            }

            if (nextNode == null) {
                return null;
            }

            return nextNode.search(token, token_type);
        }
    }

    public enum TOKEN_TYPE {
        REFRESH_TOKEN,
        AUTHORISATION_TOKEN
    }
}
