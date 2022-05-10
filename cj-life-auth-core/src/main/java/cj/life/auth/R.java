package cj.life.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * @description: Rest API 接口方法返回类型定义
 * @author: zheng
 * @date: Created in 2021/1/26 13:25
 * @version: 0.0.1
 * @modified By:
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class R<T> implements Serializable {
    private String code;
    private String message;
    private T data;

    public T getData() {
        return data;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public static <T> R<T> of( String code, String msg,T data) {
        return new R<>(code, msg, data);
    }

    public static <T> R<T> of(ResultCode rc,T data) {
        return new R<>(rc.code(), rc.message(), data);
    }
}

