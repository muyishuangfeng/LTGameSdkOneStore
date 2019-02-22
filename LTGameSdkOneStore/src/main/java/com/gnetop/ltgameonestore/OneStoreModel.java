package com.gnetop.ltgameonestore;

public class OneStoreModel {


    /**
     * orderId : ONESTORE7_000000000000000000000000270010
     * packageName : com.gnetop.ltgameproject.one
     * productId : kr.ltgames.10usd
     * purchaseTime : 1547608924041
     * purchaseId : SANDBOX3000000272008
     * developerPayload : >0s6/k@I%-nd~{{K&/Ye
     */
     //orderId
    private String orderId;
    //包名
    private String packageName;
    //产品ID
    private String productId;
    //购买时间
    private long purchaseTime;
    //购买ID
    private String purchaseId;
    //developerPayload
    private String developerPayload;

    public String getOrderId() {
        return orderId;
    }

    public void setOrderId(String orderId) {
        this.orderId = orderId;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getProductId() {
        return productId;
    }

    public void setProductId(String productId) {
        this.productId = productId;
    }

    public long getPurchaseTime() {
        return purchaseTime;
    }

    public void setPurchaseTime(long purchaseTime) {
        this.purchaseTime = purchaseTime;
    }

    public String getPurchaseId() {
        return purchaseId;
    }

    public void setPurchaseId(String purchaseId) {
        this.purchaseId = purchaseId;
    }

    public String getDeveloperPayload() {
        return developerPayload;
    }

    public void setDeveloperPayload(String developerPayload) {
        this.developerPayload = developerPayload;
    }
}
