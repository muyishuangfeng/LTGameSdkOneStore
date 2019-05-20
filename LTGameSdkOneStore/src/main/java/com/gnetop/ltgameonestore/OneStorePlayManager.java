package com.gnetop.ltgameonestore;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.gnetop.ltgamecommon.impl.OnCreateOrderFailedListener;
import com.gnetop.ltgamecommon.impl.OnCreateOrderListener;
import com.gnetop.ltgamecommon.impl.onOneStoreSupportListener;
import com.gnetop.ltgamecommon.impl.onOneStoreUploadListener;
import com.gnetop.ltgamecommon.login.LoginBackManager;
import com.gnetop.ltgamecommon.model.OneStoreResult;
import com.gnetop.ltgamecommon.util.PreferencesUtils;
import com.google.gson.Gson;
import com.onestore.iap.api.IapResult;
import com.onestore.iap.api.PurchaseClient;
import com.onestore.iap.api.PurchaseData;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;


public class OneStorePlayManager {

    @SuppressLint("StaticFieldLeak")
    private static PurchaseClient mPurchaseClient;
    private static final int IAP_API_VERSION = 5;
    private static final String TAG = OneStorePlayManager.class.getSimpleName();
    private static final String KEY_FACTORY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static String mPublicKey;
    private static boolean mIsInit = false;
    private static final String PURCHASE_ID = "PURCHASE_ID";
    private static final String DEVELOPER_PAYLOAD = "DEVELOPER_PAYLOAD";
    //是否消费
    private static boolean mISConsume = false;

    private static void init(Context context, String publickey) {
        mPurchaseClient = new PurchaseClient(context, publickey);
        mPublicKey = publickey;
    }


    /**
     * 初始化
     *
     * @param context   上下文
     * @param mListener 回调
     */
    public static void initOneStore(final Activity context, final String publickey,
                                    final String productType,
                                    final String LTAppID, final String LTAppKey,
                                    final int testID,
                                    final onOneStoreSupportListener mListener,
                                    final onOneStoreUploadListener mUploadListener) {
        if (!mIsInit) {
            init(context, publickey);
            mIsInit = true;
        }
        if (mPurchaseClient != null) {
            mPurchaseClient.connect(new PurchaseClient.ServiceConnectionListener() {
                @Override
                public void onConnected() {
                    if (mListener != null) {
                        mListener.onOneStoreConnected();
                    }
                    checkBillingSupportedAndLoadPurchases(context, LTAppID, LTAppKey, testID, productType, mListener, mUploadListener);
                }

                @Override
                public void onDisconnected() {
                    if (mListener != null) {
                        mListener.onOneStoreDisConnected();
                    }
                }

                @Override
                public void onErrorNeedUpdateException() {
                    if (mListener != null) {
                        mListener.onOneStoreFailed(OneStoreResult.RESULT_CONNECTED_NEED_UPDATE);
                        PurchaseClient.launchUpdateOrInstallFlow(context);
                    }
                }
            });
        }
    }

    /**
     * 检查是否支持
     */
    private static void checkBillingSupportedAndLoadPurchases(final Context context,
                                                              final String LTAppID, final String LTAppKey,
                                                              final int testID, final String productType,
                                                              final onOneStoreSupportListener mListener,
                                                              final onOneStoreUploadListener mUploadListener) {
        if (mPurchaseClient == null) {
            if (mListener != null) {
                mListener.onOneStoreClientFailed("PurchaseClient is not initialized");
            }
        } else {
            mPurchaseClient.isBillingSupportedAsync(IAP_API_VERSION, new PurchaseClient.BillingSupportedListener() {
                @Override
                public void onSuccess() {
                    mListener.onOneStoreSuccess(OneStoreResult.RESULT_BILLING_OK);
                    // 然后通过对托管商品和每月采购历史记录的呼叫接收采购历史记录信息。
                    //loadPurchases((Activity) context,  mListener);
                    Log.e(TAG, "isBillingSupportedAsync : RESULT_BILLING_OK");
                    mPurchaseClient.queryPurchasesAsync(IAP_API_VERSION, productType,
                            new PurchaseClient.QueryPurchaseListener() {
                                @Override
                                public void onSuccess(List<PurchaseData> purchaseDataList, String productType) {
                                    Log.e(TAG, "queryPurchasesAsync onSuccess, " + purchaseDataList.toString());
                                    for (PurchaseData purchase : purchaseDataList) {
                                        consumeItem((Activity) context, LTAppID, LTAppKey, testID, purchase, mListener, mUploadListener);
                                    }
                                }

                                @Override
                                public void onError(IapResult iapResult) {
                                    mListener.onOneStoreError("onError====" + iapResult.toString());
                                }

                                @Override
                                public void onErrorRemoteException() {
                                    mListener.onOneStoreFailed(OneStoreResult.RESULT_PURCHASES_REMOTE_ERROR);
                                }

                                @Override
                                public void onErrorSecurityException() {
                                    mListener.onOneStoreFailed(OneStoreResult.RESULT_PURCHASES_SECURITY_ERROR);
                                }

                                @Override
                                public void onErrorNeedUpdateException() {
                                    mListener.onOneStoreFailed(OneStoreResult.RESULT_PURCHASES_NEED_UPDATE);
                                    PurchaseClient.launchUpdateOrInstallFlow((Activity) context);
                                }
                            });
                }

                @Override
                public void onError(IapResult iapResult) {
                    mListener.onOneStoreError(iapResult.toString());
                }

                @Override
                public void onErrorRemoteException() {
                    mListener.onOneStoreFailed(OneStoreResult.RESULT_BILLING_REMOTE_ERROR);
                }

                @Override
                public void onErrorSecurityException() {
                    mListener.onOneStoreFailed(OneStoreResult.RESULT_BILLING_SECURITY_ERROR);
                }

                @Override
                public void onErrorNeedUpdateException() {
                    mListener.onOneStoreFailed(OneStoreResult.RESULT_BILLING_NEED_UPDATE);
                    PurchaseClient.launchUpdateOrInstallFlow((Activity) context);
                }
            });
        }
    }


    /**
     * 在管理商品 (inapp) 后或历史记录视图完成后, 消耗托管商品的消费.
     *
     * @param purchaseData 产品数据
     */
    private static void consumeItem(final Activity context, final String LTAppID, final String LTAppKey,
                                    final int testID,
                                    final PurchaseData purchaseData,
                                    final onOneStoreSupportListener mListener,
                                    final onOneStoreUploadListener mUploadListener) {
        if (mPurchaseClient == null) {
            mListener.onOneStoreFailed(OneStoreResult.RESULT_PURCHASES_NEED_UPDATE);
            Log.e(TAG, "PurchaseClient is not initialized");
            return;
        }
        mPurchaseClient.consumeAsync(IAP_API_VERSION, purchaseData,
                new PurchaseClient.ConsumeListener() {
                    @Override
                    public void onSuccess(PurchaseData purchaseData) {
                        Log.e(TAG, "consumeAsync===success");
                        mListener.onOneStoreSuccess(OneStoreResult.RESULT_CONSUME_OK);
                        if (!TextUtils.isEmpty(PreferencesUtils.getString(context, PURCHASE_ID)) &&
                                !TextUtils.isEmpty(PreferencesUtils.getString(context, DEVELOPER_PAYLOAD))) {
                            uploadServer(context, LTAppID, LTAppKey, PreferencesUtils.getString(context, PURCHASE_ID),
                                    PreferencesUtils.getString(context, DEVELOPER_PAYLOAD), testID, mUploadListener);
                        } else if (mISConsume) {
                            uploadServer(context, LTAppID, LTAppKey, purchaseData.getPurchaseId(),
                                    purchaseData.getDeveloperPayload(), testID, mUploadListener);
                        }
                        mISConsume = false;
                    }

                    @Override
                    public void onError(IapResult iapResult) {
                        mListener.onOneStoreError(iapResult.toString());
                        Log.e(TAG, "consumeAsync onError,  消费错误" + iapResult.toString());
                    }

                    @Override
                    public void onErrorRemoteException() {
                        mListener.onOneStoreFailed(OneStoreResult.RESULT_CONSUME_REMOTE_ERROR);
                        Log.e(TAG, "consumeAsync onError,  消费连接失败");
                    }

                    @Override
                    public void onErrorSecurityException() {
                        mListener.onOneStoreFailed(OneStoreResult.RESULT_CONSUME_SECURITY_ERROR);
                        Log.e(TAG, "consumeAsync onError,  消费应用状态异常下请求支付");
                    }

                    @Override
                    public void onErrorNeedUpdateException() {
                        mListener.onOneStoreFailed(OneStoreResult.RESULT_CONSUME_NEED_UPDATE);
                        Log.e(TAG, "consumeAsync onError,  消费产品需要更新");
                    }
                });
    }


    /**
     * oneStore回调
     *
     * @param requestCode     请求码
     * @param resultCode      结果码
     * @param selfRequestCode 自定义请求码
     */
    public static void onActivityResult(Context context, String LTAppID, String LTAppKey,
                                        int testID, int requestCode, int resultCode, Intent data, int selfRequestCode,
                                        final onOneStoreUploadListener mListener, final onOneStoreSupportListener mSupportListener) {
        if (requestCode == selfRequestCode)
            if (resultCode == Activity.RESULT_OK) {
                if (!mPurchaseClient.handlePurchaseData(data)) {
                    Log.e(TAG, "onActivityResult handlePurchaseData false ");
                } else {
                    String signature = data.getStringExtra("purchaseSignature");
                    String purchaseData = data.getStringExtra("purchaseData");
                    Gson gson = new Gson();
                    PurchaseData mPurchaseData = gson.fromJson(purchaseData, PurchaseData.class);
                    if (mPurchaseData != null) {
                        PreferencesUtils.putString(context, PURCHASE_ID, mPurchaseData.getPurchaseId());
                        PreferencesUtils.putString(context, DEVELOPER_PAYLOAD, mPurchaseData.getDeveloperPayload());
                        consumeItem((Activity) context, LTAppID, LTAppKey, testID, mPurchaseData, mSupportListener, mListener);
                        Log.e(TAG, "onActivityResult handlePurchaseData true " + mPurchaseData.toString() + "==="
                                + signature);
                    }
                }
            } else {
                Log.e(TAG, "onActivityResult user canceled");
            }
    }

    /**
     * 获得商品
     *
     * @param productId       商品ID
     * @param selfRequestCode 请求码
     * @param productName     产品名称
     */
    public static void getProduct(final Activity context, final String LTAppID, final String LTAppKey,
                                  int selfRequestCode, String productName,
                                  final String packageID, final String gid, final Map<String, Object> params,
                                  final String productId, String type,
                                  final onOneStoreSupportListener mListener, final OnCreateOrderFailedListener mCreateListener) {
        if (!mISConsume) {
            if (!mIsInit) {
                init(context, mPublicKey);
            } else {
                getLTOrderID(context, LTAppID, LTAppKey, packageID, gid, params, selfRequestCode, productName, productId, type,
                        mListener,
                        mCreateListener);

            }
        }
    }

    /**
     * 购买
     */
    private static void launchPurchase(final Activity context,
                                       int selfRequestCode, String productName,
                                       final String productId, String type, final String devPayLoad,
                                       final onOneStoreSupportListener mListener) {
        if (mPurchaseClient != null) {
            mPurchaseClient.launchPurchaseFlowAsync(IAP_API_VERSION,
                    context, selfRequestCode, productId, productName,
                    type, devPayLoad, "",
                    false, new PurchaseClient.PurchaseFlowListener() {

                        @Override
                        public void onSuccess(PurchaseData purchaseData) {
                            Log.e(TAG, "launchPurchaseFlowAsy======= " + purchaseData.getDeveloperPayload() + "====" + devPayLoad);

                        }

                        @Override
                        public void onError(IapResult result) {
                            Log.e(TAG, "launchPurchaseFlowAsync onError, " + result.toString());
                            mListener.onOneStoreError(result.toString());
                        }

                        @Override
                        public void onErrorRemoteException() {
                            Log.e(TAG, "launchPurchaseFlowAsync onError=====onErrorRemoteException");
                            mListener.onOneStoreFailed(OneStoreResult.RESULT_PURCHASES_FLOW_REMOTE_ERROR);
                        }

                        @Override
                        public void onErrorSecurityException() {
                            Log.e(TAG, "launchPurchaseFlowAsync onError=====onErrorSecurityException");
                            mListener.onOneStoreFailed(OneStoreResult.RESULT_PURCHASES_FLOW_SECURITY_ERROR);
                        }

                        @Override
                        public void onErrorNeedUpdateException() {
                            Log.e(TAG, "launchPurchaseFlowAsync onError=====onErrorNeedUpdateException");
                            mListener.onOneStoreFailed(OneStoreResult.RESULT_PURCHASES_FLOW_NEED_UPDATE);
                            PurchaseClient.launchUpdateOrInstallFlow(context);
                        }
                    });
        }
    }


    /**
     * 获取乐推订单ID
     *
     * @param LTAppID   乐推AppID
     * @param LTAppKey  乐推AppKey
     * @param packageID 项目对应的包名
     * @param gid       服务器商品ID
     * @param params    游戏自定义内容
     */
    private static void getLTOrderID(final Activity activity, final String LTAppID, final String LTAppKey,
                                     String packageID, String gid, Map<String, Object> params,
                                     final int selfRequestCode, final String productName,
                                     final String productId, final String type,
                                     final onOneStoreSupportListener mListener,
                                     final OnCreateOrderFailedListener mOrderListener) {
        Map<String, Object> map = new WeakHashMap<>();
        map.put("package_id", packageID);
        map.put("gid", gid);
        map.put("custom", params);
        LoginBackManager.createOrder(activity, LTAppID,
                LTAppKey, map, new OnCreateOrderListener() {
                    @Override
                    public void onOrderSuccess(String result) {
                        launchPurchase(activity, selfRequestCode, productName, productId,
                                type, result, mListener);
                        mISConsume = true;
                    }

                    @Override
                    public void onOrderFailed(Throwable ex) {
                        if (mOrderListener != null) {
                            mOrderListener.onCreateOrderFailed(ex.getMessage());
                        }
                        Log.e(TAG, ex.getMessage());
                    }

                    @Override
                    public void onOrderError(String error) {
                        if (mOrderListener != null) {
                            mOrderListener.onCreateOrderError(error);
                        }
                        Log.e(TAG, error);
                    }
                });
    }

    private static void uploadServer(final Context context, String LTAppID, final String LTAppKey,
                                     String purchase_id, String devPayLoad, int testID,
                                     final onOneStoreUploadListener mListener) {
        Log.e(TAG, "uploadServer===========start");
        Map<String, Object> map = new WeakHashMap<>();
        map.put("purchase_id", purchase_id);
        map.put("lt_order_id", devPayLoad);
        map.put("pay_test", testID);
        LoginBackManager.oneStorePlay(LTAppID, LTAppKey, map, new onOneStoreUploadListener() {
            @Override
            public void onOneStoreUploadSuccess(int result) {
                mListener.onOneStoreUploadSuccess(result);
                mISConsume = false;
                if (!TextUtils.isEmpty(PreferencesUtils.getString(context, PURCHASE_ID))) {
                    PreferencesUtils.remove(context, PURCHASE_ID);
                }
                if (!TextUtils.isEmpty(PreferencesUtils.getString(context, DEVELOPER_PAYLOAD))) {
                    PreferencesUtils.remove(context, DEVELOPER_PAYLOAD);
                }
            }

            @Override
            public void onOneStoreUploadFailed(Throwable error) {
                mListener.onOneStoreUploadFailed(error);
            }
        });
    }

    /**
     * 释放
     */
    public static void release() {
        mISConsume = false;
        mIsInit = false;
        if (mPurchaseClient != null) {
            mPurchaseClient.terminate();
            mPurchaseClient = null;
        }

    }

    private static boolean verifyPurchase(String signedData, String signature) {
        if (TextUtils.isEmpty(signedData) || TextUtils.isEmpty(signature)) {
            return false;
        }
        PublicKey key = generatePublicKey(mPublicKey);
        return verify(key, signedData, signature);
    }

    private static PublicKey generatePublicKey(String encodedPublicKey) {
        try {
            byte[] decodedKey = Base64.decode(encodedPublicKey, Base64.DEFAULT);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("RSA not available", e);
        } catch (InvalidKeySpecException e) {
            Log.e(TAG, "Invalid key specification.");
            throw new IllegalArgumentException(e);
        }
    }

    private static boolean verify(PublicKey publicKey, String signedData, String signature) {
        try {
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(signedData.getBytes());
            if (!sig.verify(Base64.decode(signature, Base64.DEFAULT))) {
                Log.e(TAG, "Signature verification failed.");
                return false;
            }
            return true;
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "NoSuchAlgorithmException.");
        } catch (InvalidKeyException e) {
            Log.e(TAG, "Invalid key specification.");
        } catch (SignatureException e) {
            Log.e(TAG, "SignatureTest exception.");
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "Base64 decoding failed.");
        }
        return false;
    }


}