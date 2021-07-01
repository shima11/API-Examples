package io.agora.advancedvideo.externvideosource;

import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.opengl.GLES20;

import androidx.annotation.NonNull;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import io.agora.base.VideoFrame;
import io.agora.base.internal.video.GlRectDrawer;
import io.agora.base.internal.video.GlTextureFrameBuffer;
import io.agora.base.internal.video.RendererCommon;

/**
 * @author chenhengfei(Aslanchen)
 * @date 2021/7/1
 */
public class TextureIdHelp {
    private GlTextureFrameBuffer bitmapTextureFramebuffer;
    private GlRectDrawer textureDrawer;

    public Bitmap textureIdToBitmap(int width, int height, int rotation, VideoFrame.TextureBuffer.Type type, int textureId, Matrix transformMatrix) {
        if (textureDrawer == null) {
            textureDrawer = new GlRectDrawer();
        }

        if (bitmapTextureFramebuffer == null) {
            bitmapTextureFramebuffer = new GlTextureFrameBuffer(GLES20.GL_RGBA);
        }

        int frameWidth = rotation % 180 == 0 ? width : height;
        int frameHeight = rotation % 180 == 0 ? height : width;
        bitmapTextureFramebuffer.setSize(frameWidth, frameHeight);
        GLES20.glBindFramebuffer(GLES20.GL_FRAMEBUFFER, bitmapTextureFramebuffer.getFrameBufferId());
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT);
        Matrix renderMatrix = new Matrix();
        renderMatrix.preTranslate(0.5F, 0.5F);
        renderMatrix.preRotate((float) rotation + 180); // need rotate 180 from texture to bitmap
        renderMatrix.preTranslate(-0.5F, -0.5F);
        renderMatrix.postConcat(transformMatrix);
        float[] finalGlMatrix = RendererCommon.convertMatrixFromAndroidGraphicsMatrix(renderMatrix);
        if (type == VideoFrame.TextureBuffer.Type.OES) {
            textureDrawer.drawOes(textureId, finalGlMatrix, frameWidth, frameHeight, 0, 0, frameWidth, frameHeight);
        } else {
            textureDrawer.drawRgb(textureId, finalGlMatrix, frameWidth, frameHeight, 0, 0, frameWidth, frameHeight);
        }

        final ByteBuffer bitmapBuffer = ByteBuffer.allocateDirect(frameWidth * frameHeight * 4);
        GLES20.glViewport(0, 0, frameWidth, frameHeight);
        GLES20.glReadPixels(
                0, 0, frameWidth, frameHeight, GLES20.GL_RGBA, GLES20.GL_UNSIGNED_BYTE, bitmapBuffer);

        GLES20.glBindFramebuffer(GLES20.GL_FRAMEBUFFER, 0);

        Bitmap mBitmap = Bitmap.createBitmap(frameWidth, frameHeight, Bitmap.Config.ARGB_8888);
        mBitmap.copyPixelsFromBuffer(bitmapBuffer);
        return mBitmap;
    }

    public void release() {
        if (textureDrawer != null) {
//            textureDrawer.release();
            textureDrawer = null;
        }
        if (bitmapTextureFramebuffer != null) {
            bitmapTextureFramebuffer.release();
            bitmapTextureFramebuffer = null;
        }
    }

    public void saveBitmap(@NonNull File file, @NonNull Bitmap bmp) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            bmp.compress(Bitmap.CompressFormat.JPEG, 100, fos);
            fos.flush();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
