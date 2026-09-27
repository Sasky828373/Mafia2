package com.m2port.bootstrap;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.TextView;

public final class MainActivity extends Activity {
    static { System.loadLibrary("m2bootstrap"); }
    private static native String nativeProbe();

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView output = new TextView(this);
        output.setText(nativeProbe());
        output.setTextColor(Color.WHITE);
        output.setBackgroundColor(Color.BLACK);
        output.setTextSize(16f);
        output.setGravity(Gravity.START | Gravity.TOP);
        output.setPadding(32, 32, 32, 32);
        setContentView(output);
    }
}
