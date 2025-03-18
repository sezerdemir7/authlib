package com.inonu.authlib.dto;

public class PermissionRequest{
    private String userId;
    private Long unitId;

    public PermissionRequest(String userId, Long unitId) {
        this.userId = userId;
        this.unitId = unitId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Long getUnitId() {
        return unitId;
    }

    public void setUnitId(Long unitId) {
        this.unitId = unitId;
    }
}
