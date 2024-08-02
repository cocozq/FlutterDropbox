package com.mix1009.dropbox;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;

import androidx.annotation.NonNull;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.embedding.engine.plugins.activity.ActivityAware;
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

import com.dropbox.core.DbxAppInfo;
import com.dropbox.core.json.JsonReadException;
import com.dropbox.core.DbxAuthFinish;
import com.dropbox.core.DbxDownloader;
import com.dropbox.core.oauth.DbxCredential;
import com.dropbox.core.DbxException;
import com.dropbox.core.DbxRequestConfig;
import com.dropbox.core.DbxWebAuth;
import com.dropbox.core.android.Auth;
import com.dropbox.core.android.AuthActivity;
import com.dropbox.core.util.IOUtil;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.FileMetadata;
import com.dropbox.core.v2.files.GetTemporaryLinkResult;
import com.dropbox.core.v2.files.ListFolderResult;
import com.dropbox.core.v2.files.Metadata;
import com.dropbox.core.v2.files.UploadBuilder;
import com.dropbox.core.v2.files.WriteMode;
import com.dropbox.core.v2.users.FullAccount;
import com.dropbox.core.http.OkHttp3Requestor;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


/** DropboxPlugin */
public class DropboxPlugin implements FlutterPlugin, MethodCallHandler, ActivityAware {
  private static final String CHANNEL_NAME = "dropbox";
  @SuppressLint("StaticFieldLeak")
  private static Activity activity;
  private MethodChannel channel;
  private ExecutorService executorService;
  private long fileSize = 0;

  @Override
  public void onAttachedToEngine(@NonNull FlutterPluginBinding binding) {
    setupChannel(binding.getBinaryMessenger(), binding.getApplicationContext());
  }

  @Override
  public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
    teardownChannel();
  }


  public static void registerWith(Registrar registrar) {
    if (registrar.activity() != null) {
      DropboxPlugin.activity = registrar.activity();
    }
    DropboxPlugin plugin = new DropboxPlugin();
    plugin.setupChannel(registrar.messenger(), registrar.context());
  }

  private void setupChannel(BinaryMessenger messenger, Context context) {
    channel = new MethodChannel(messenger, CHANNEL_NAME);
    channel.setMethodCallHandler(this);
  }

  private void teardownChannel() {
    channel.setMethodCallHandler(null);
    channel = null;
  }

  @Override
  public void onAttachedToActivity(ActivityPluginBinding binding)
  {
    DropboxPlugin.activity = binding.getActivity();
    executorService = Executors.newFixedThreadPool(1);
  }

  @Override
  public void onDetachedFromActivityForConfigChanges() {
    DropboxPlugin.activity = null;
  }

  @Override
  public void onReattachedToActivityForConfigChanges(ActivityPluginBinding binding) {
    DropboxPlugin.activity = binding.getActivity();
  }

  @Override
  public void onDetachedFromActivity() {
    DropboxPlugin.activity = null;
  }

  protected static DbxRequestConfig sDbxRequestConfig;
  protected static DbxClientV2 client;
  protected static DbxWebAuth webAuth;
  protected static String accessToken;
  protected static DbxCredential credentials;
  protected static String clientId;
  protected static DbxAppInfo appInfo;

  boolean checkClient(Result result) {
    if (client == null) {
      String authToken = Auth.getOAuth2Token();

      if (authToken != null) {
        sDbxRequestConfig = DbxRequestConfig.newBuilder(clientId)
                .withHttpRequestor(new OkHttp3Requestor(OkHttp3Requestor.defaultOkHttpClient()))
                .build();

        client = new DbxClientV2(sDbxRequestConfig, authToken);

        accessToken = authToken;
        return true;
      }
      result.error("error", "client not logged in", null);
      return false;
    }
    return true;
  }

  @Override
  public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
    if (call.method.equals("init")) {
      String clientId = call.argument("clientId");
      String key = call.argument("key");
      String secret = call.argument("secret");
      DropboxPlugin.clientId = clientId;
      appInfo = new DbxAppInfo(key, secret);

      sDbxRequestConfig = DbxRequestConfig.newBuilder(Objects.requireNonNull(clientId))
              .withHttpRequestor(new OkHttp3Requestor(OkHttp3Requestor.defaultOkHttpClient()))
              .build();

      result.success(true);

    } else if (call.method.equals("authorizePKCE")) {
      sDbxRequestConfig = DbxRequestConfig.newBuilder(clientId)
              .withHttpRequestor(new OkHttp3Requestor(OkHttp3Requestor.defaultOkHttpClient()))
              .build();
      Auth.startOAuth2PKCE(DropboxPlugin.activity , appInfo.getKey(),sDbxRequestConfig);
      result.success(true);

    } else if (call.method.equals("authorize")) {
      Auth.startOAuth2Authentication(DropboxPlugin.activity , appInfo.getKey());
      result.success(true);

    } else if (call.method.equals("authorizeWithAccessToken")) {
      String argAccessToken = call.argument("accessToken");

      sDbxRequestConfig = DbxRequestConfig.newBuilder(clientId)
              .withHttpRequestor(new OkHttp3Requestor(OkHttp3Requestor.defaultOkHttpClient()))
              .build();

      client = new DbxClientV2(sDbxRequestConfig, Objects.requireNonNull(argAccessToken));

      accessToken = argAccessToken;
      result.success(true);

    } else if (call.method.equals("authorizeWithCredentials")) {
      String argCredentials = call.argument("credentials");
      // now de-serialize credentials
      sDbxRequestConfig = DbxRequestConfig.newBuilder(clientId)
              .withHttpRequestor(new OkHttp3Requestor(OkHttp3Requestor.defaultOkHttpClient()))
              .build();
      DbxCredential creds;
       try {
         creds = DbxCredential.Reader.readFully(argCredentials);
         client = new DbxClientV2(sDbxRequestConfig, creds);
       } catch (JsonReadException e) {
         throw new IllegalStateException("Credential data corrupted: " + e.getMessage());
       }    

      credentials = creds;
      result.success(true);

    } else if (call.method.equals("getAuthorizeUrl")) {

      if (webAuth == null) {
        webAuth = new DbxWebAuth(sDbxRequestConfig, appInfo);
      }

      DbxWebAuth.Request webAuthRequest = DbxWebAuth.newRequestBuilder()
              .withNoRedirect()
              .build();

      String authorizeUrl = webAuth.authorize(webAuthRequest);
      result.success(authorizeUrl);

    } else if (call.method.equals("unlink")) {
      client = null;
      accessToken = null;
      AuthActivity.result = null;
      // call DbxUserAuthRequests.tokenRevoke(); ?

    } else if (call.method.equals("finishAuth")) {
      String code = call.argument("code");
      finishAuth(webAuth, result, code);
    } else if (call.method.equals("getAccountName")) {
      if (!checkClient(result)) return;
      getAccountName(result);
    } else if (call.method.equals("listFolder")) {
      String path = call.argument("path");

      if (!checkClient(result)) return;
      listFolder(result, path);
    } else if (call.method.equals("remove")) {
      String path = call.argument("path");

      if (!checkClient(result)) return;
      remove(result, path);
    } else if (call.method.equals("getTemporaryLink")) {
      String path = call.argument("path");

      if (!checkClient(result)) return;
      temporaryLink(result, path);
    } else if (call.method.equals("getThumbnailBase64String")) {
      String path = call.argument("path");

      if (!checkClient(result)) return;
      thumbnailBase64String(result, path);
    } else if (call.method.equals("getAccessToken")) {
//      result.success(accessToken);
      String token = Auth.getOAuth2Token();
      if (token == null) {
        token = accessToken;
      }
      result.success(token);
    } else if (call.method.equals("getCredentials")) {
      DbxCredential myCred = Auth.getDbxCredential();
      if (myCred == null) {
        myCred = credentials;
      }
      String credString = myCred != null ? myCred.toString() : null;
      result.success(credString);

    } else if (call.method.equals("upload")) {
      String filepath = call.argument("filepath");
      String dropboxpath = call.argument("dropboxpath");
      int key = call.argument("key");

      if (!checkClient(result)) return;
      upload(result, channel, key, filepath, dropboxpath);
    } else if (call.method.equals("download")) {
      String filepath = call.argument("filepath");
      String dropboxpath = call.argument("dropboxpath");
      int key = call.argument("key");

      if (!checkClient(result)) return;
      download(result, channel, key, dropboxpath, filepath);
    } else {
      result.notImplemented();
    }
  }

  void finishAuth(DbxWebAuth webAuth, Result result, String code) {
    executorService.submit(() -> {
      String accessToken = "";
      DbxAuthFinish authFinish;
      try {
        authFinish = webAuth.finishFromCode(code);
        accessToken = authFinish.getAccessToken();
        DropboxPlugin.client = new DbxClientV2(DropboxPlugin.sDbxRequestConfig, accessToken);
        DropboxPlugin.accessToken = accessToken;
      } catch (DbxException ex) {
        System.err.println("Error in DbxWebAuth.authorize: " + ex.getMessage());
      }

      result.success(accessToken);
    });
  }

  void getAccountName(Result result) {
    executorService.submit(() -> {
      String name = "";
      FullAccount account = null;
      try {
        account = DropboxPlugin.client.users().getCurrentAccount();
        name = account.getName().getDisplayName();
      } catch (DbxException e) {
        name = e.getMessage();
      }

      result.success(name);
    });
  }

  void listFolder(Result result, String path) {
    executorService.submit(() -> {
      List<Map<String, Object>> paths = new ArrayList<>();
      ListFolderResult listFolderResult;
      try {
        listFolderResult = DropboxPlugin.client.files().listFolder(path);
        String pattern = "yyyyMMdd HHmmss";
        @SuppressLint("SimpleDateFormat") DateFormat df = new SimpleDateFormat(pattern);

        while (true) {

          for (Metadata metadata : listFolderResult.getEntries()) {
            Map<String, Object> map = new HashMap<>();
            map.put("name", metadata.getName());
            map.put("pathLower", metadata.getPathLower());
            map.put("pathDisplay", metadata.getPathDisplay());

            if (metadata instanceof FileMetadata) {
              FileMetadata fileMetadata = (FileMetadata) metadata;
              map.put("filesize", fileMetadata.getSize());
              map.put("clientModified", df.format(fileMetadata.getClientModified()));
              map.put("serverModified", df.format(fileMetadata.getServerModified()));
            }

            paths.add(map);
          }

          if (!listFolderResult.getHasMore()) {
            break;
          }

          listFolderResult = DropboxPlugin.client.files().listFolderContinue(listFolderResult.getCursor());
        }
      } catch (DbxException e) {
        e.printStackTrace();
      }

      result.success(paths);
    });
  }

  void remove(Result result, String path) {
    executorService.submit(() -> {
      boolean res = false;
      try {
        client.files().deleteV2(path);
        res = true;
      } catch (DbxException e) {
        e.printStackTrace();
      }

      result.success(res);
    });
  }

  void temporaryLink(Result result, String path) {
    executorService.submit(() -> {
      String link;
      GetTemporaryLinkResult linkResult;
      try {
        linkResult = client.files().getTemporaryLink(path);
        link = linkResult.getLink();
      } catch (DbxException e) {
        link = e.getMessage();
      }

      result.success(link);
    });
  }

  void thumbnailBase64String(Result result, String path) {
    executorService.submit(() -> {
      String res;
      try {
        DbxDownloader<FileMetadata> downloader = client.files().getThumbnail(path);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        downloader.download(bo);
        res = Base64.encodeToString(bo.toByteArray(), Base64.DEFAULT);

      } catch (Exception e) {
        e.printStackTrace();
        res = e.getMessage();
      }

      result.success(res);
    });
  }

  void upload(Result result, MethodChannel channel, long key, String filePath, String dropboxPath) {
    executorService.submit(() -> {
      String res = "";
      UploadBuilder uploadBuilder;
      try {
        InputStream in = new FileInputStream(filePath);

        uploadBuilder = client.files().uploadBuilder(dropboxPath).withMode(WriteMode.OVERWRITE).withAutorename(true).withMute(false);

        uploadBuilder.uploadAndFinish(in, new IOUtil.ProgressListener() {
          @Override
          public void onProgress(long bytesWritten) {
            final long written = bytesWritten;
            new Handler(Looper.getMainLooper()).post(new Runnable () {
              @Override
              public void run () {
                // MUST RUN ON MAIN THREAD !
                List<Long> ret = new ArrayList<Long>();
                ret.add(key);
                ret.add(written);
                channel.invokeMethod("progress", ret, null);
              }
            });
          }
        });
      } catch (Exception e) {
        e.printStackTrace();
        res = e.getMessage();
      }

      result.success(res);
    });
  }

  void download(Result result, MethodChannel channel, long key, String dropboxPath, String filePath) {
    executorService.submit(() -> {
      String res = "";
      try {
        Metadata metadata = client.files().getMetadata(dropboxPath);

        if (metadata instanceof FileMetadata) {
          FileMetadata fileMetadata = (FileMetadata) metadata;
          fileSize = fileMetadata.getSize();
        }

        DbxDownloader<FileMetadata> downloader = client.files().download(dropboxPath);
        OutputStream out = new FileOutputStream(filePath);
        downloader.download(out, bytesRead -> {
          final long read = bytesRead;
          new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
              // MUST RUN ON MAIN THREAD !
              List<Long> ret = new ArrayList<>();
              ret.add(key);
              ret.add(read);
              ret.add(fileSize);
              channel.invokeMethod("progress", ret, null);
            }
          });
        });

      } catch (FileNotFoundException e) {
        e.printStackTrace();
        res = e.getMessage();
      } catch (IOException e) {
        e.printStackTrace();
      } catch (DbxException e) {
        e.printStackTrace();
        res = e.getMessage();
      }

      result.success(res);
    });
  }

}

