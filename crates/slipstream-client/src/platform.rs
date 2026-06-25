#![cfg(target_os = "android")]

use jni::objects::{JObject, JValue};
use jni::JavaVM;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;
use tracing::warn;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

const ANDROID_LOG_DEBUG: c_int = 3;
const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_WARN: c_int = 5;
const ANDROID_LOG_ERROR: c_int = 6;

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

pub(crate) fn set_java_vm(vm: JavaVM) {
    let _ = JAVA_VM.set(vm);
}

fn log_android(priority: c_int, tag: &str, message: &str) {
    let tag = CString::new(tag).unwrap_or_else(|_| CString::new("SlipstreamNative").unwrap());
    let message = CString::new(message.replace('\0', "\\0"))
        .unwrap_or_else(|_| CString::new("log message contained invalid bytes").unwrap());
    unsafe {
        let _ = __android_log_write(priority, tag.as_ptr(), message.as_ptr());
    }
}

fn log_app(priority: c_int, tag: &str, message: &str) {
    let Some(vm) = JAVA_VM.get() else {
        return;
    };
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(_) => return,
    };
    let Ok(tag_obj) = env.new_string(tag) else {
        return;
    };
    let Ok(message_obj) = env.new_string(message) else {
        return;
    };
    let tag_obj = JObject::from(tag_obj);
    let message_obj = JObject::from(message_obj);
    let _ = env.call_static_method(
        "app/slipnet/tunnel/SlipstreamBridge",
        "nativeLog",
        "(ILjava/lang/String;Ljava/lang/String;)V",
        &[
            JValue::Int(priority),
            JValue::Object(&tag_obj),
            JValue::Object(&message_obj),
        ],
    );
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

fn log_both(priority: c_int, tag: &str, message: &str) {
    log_android(priority, tag, message);
    log_app(priority, tag, message);
}

pub(crate) fn log_debug(tag: &str, message: &str) {
    log_both(ANDROID_LOG_DEBUG, tag, message);
}

pub(crate) fn log_info(tag: &str, message: &str) {
    log_both(ANDROID_LOG_INFO, tag, message);
}

pub(crate) fn log_warn(tag: &str, message: &str) {
    log_both(ANDROID_LOG_WARN, tag, message);
}

pub(crate) fn log_error(tag: &str, message: &str) {
    log_both(ANDROID_LOG_ERROR, tag, message);
}

pub(crate) fn protect_socket_fd(fd: i32) -> bool {
    let Some(vm) = JAVA_VM.get() else {
        warn!(
            "Android socket protection requested before JNI_OnLoad; continuing because SlipNet excludes itself from the VPN"
        );
        return true;
    };
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(err) => {
            warn!(
                "Could not attach thread for Android socket protection: {}; continuing because SlipNet excludes itself from the VPN",
                err
            );
            return true;
        }
    };
    match env.call_static_method(
        "app/slipnet/tunnel/SlipstreamBridge",
        "protectSocket",
        "(I)Z",
        &[JValue::Int(fd)],
    ) {
        Ok(value) => match value.z() {
            Ok(true) => true,
            Ok(false) => {
                warn!(
                    "Android VpnService.protect({}) returned false; continuing because SlipNet excludes itself from the VPN",
                    fd
                );
                true
            }
            Err(err) => {
                warn!(
                    "Android socket protection returned a non-boolean result for fd {}: {}; continuing because SlipNet excludes itself from the VPN",
                    fd, err
                );
                true
            }
        },
        Err(err) => {
            warn!(
                "Android socket protection failed for fd {}: {}; continuing because SlipNet excludes itself from the VPN",
                fd, err
            );
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            true
        }
    }
}
