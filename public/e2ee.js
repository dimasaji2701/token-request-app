!(function (e, r) {
  "object" == typeof exports && "object" == typeof module
    ? (module.exports = r())
    : "function" == typeof define && define.amd
    ? define([], r)
    : "object" == typeof exports
    ? (exports.forge = r())
    : (e.forge = r());
})(this, function () {
  return (function (e) {
    var r = {};
    function n(a) {
      if (r[a]) return r[a].exports;
      var s = (r[a] = { i: a, l: !1, exports: {} });
      return e[a].call(s.exports, s, s.exports, n), (s.l = !0), s.exports;
    }
    return (
      (n.m = e),
      (n.c = r),
      (n.d = function (e, r, a) {
        n.o(e, r) || Object.defineProperty(e, r, { enumerable: !0, get: a });
      }),
      (n.r = function (e) {
        "undefined" != typeof Symbol &&
          Symbol.toStringTag &&
          Object.defineProperty(e, Symbol.toStringTag, { value: "Module" }),
          Object.defineProperty(e, "__esModule", { value: !0 });
      }),
      (n.t = function (e, r) {
        if (
          (1 & r && (e = n(e)),
          8 & r || (4 & r && "object" == typeof e && e && e.__esModule))
        )
          return e;
        var a = Object.create(null);
        if (
          (n.r(a),
          Object.defineProperty(a, "default", { enumerable: !0, value: e }),
          2 & r && "string" != typeof e)
        )
          for (var s in e)
            n.d(
              a,
              s,
              function (r) {
                return e[r];
              }.bind(null, s)
            );
        return a;
      }),
      (n.n = function (e) {
        var r =
          e && e.__esModule
            ? function () {
                return e.default;
              }
            : function () {
                return e;
              };
        return n.d(r, "a", r), r;
      }),
      (n.o = function (e, r) {
        return Object.prototype.hasOwnProperty.call(e, r);
      }),
      (n.p = ""),
      n((n.s = 32))
    );
  })([
    function (e, r) {
      e.exports = { options: { usePureJavaScript: !1 } };
    },
    function (e, r, n) {
      (function (r) {
        var a = n(0),
          s = n(35),
          o = (e.exports = a.util = a.util || {});
        function c(e) {
          if (8 !== e && 16 !== e && 24 !== e && 32 !== e)
            throw Error("Only 8, 16, 24, or 32 bits supported: " + e);
        }
        function u(e) {
          if (((this.data = ""), (this.read = 0), "string" == typeof e))
            this.data = e;
          else if (o.isArrayBuffer(e) || o.isArrayBufferView(e)) {
            if ("undefined" != typeof Buffer && e instanceof Buffer)
              this.data = e.toString("binary");
            else {
              var r = new Uint8Array(e);
              try {
                this.data = String.fromCharCode.apply(null, r);
              } catch (n) {
                for (var a = 0; a < r.length; ++a) this.putByte(r[a]);
              }
            }
          } else
            (e instanceof u ||
              ("object" == typeof e &&
                "string" == typeof e.data &&
                "number" == typeof e.read)) &&
              ((this.data = e.data), (this.read = e.read));
          this._constructedStringLength = 0;
        }
        "undefined" != typeof process && process.nextTick && !process.browser
          ? ((o.nextTick = process.nextTick),
            "function" == typeof setImmediate
              ? (o.setImmediate = setImmediate)
              : (o.setImmediate = o.nextTick))
          : "function" == typeof setImmediate
          ? ((o.setImmediate = function () {
              return setImmediate.apply(void 0, arguments);
            }),
            (o.nextTick = function (e) {
              return setImmediate(e);
            }))
          : (o.nextTick = o.setImmediate),
          (o.isNodejs =
            "undefined" != typeof process &&
            process.versions &&
            process.versions.node),
          (o.globalScope = o.isNodejs ? r : self),
          (o.isArray =
            Array.isArray ||
            function (e) {
              return "[object Array]" === Object.prototype.toString.call(e);
            }),
          (o.isArrayBuffer = function (e) {
            return (
              "undefined" != typeof ArrayBuffer && e instanceof ArrayBuffer
            );
          }),
          (o.isArrayBufferView = function (e) {
            return e && o.isArrayBuffer(e.buffer) && void 0 !== e.byteLength;
          }),
          (o.ByteBuffer = u),
          (o.ByteStringBuffer = u),
          (o.ByteStringBuffer.prototype._optimizeConstructedString = function (
            e
          ) {
            (this._constructedStringLength += e),
              this._constructedStringLength > 4096 &&
                (this.data.substr(0, 1), (this._constructedStringLength = 0));
          }),
          (o.ByteStringBuffer.prototype.length = function () {
            return this.data.length - this.read;
          }),
          (o.ByteStringBuffer.prototype.isEmpty = function () {
            return 0 >= this.length();
          }),
          (o.ByteStringBuffer.prototype.putByte = function (e) {
            return this.putBytes(String.fromCharCode(e));
          }),
          (o.ByteStringBuffer.prototype.fillWithByte = function (e, r) {
            e = String.fromCharCode(e);
            for (var n = this.data; r > 0; )
              1 & r && (n += e), (r >>>= 1) > 0 && (e += e);
            return (this.data = n), this._optimizeConstructedString(r), this;
          }),
          (o.ByteStringBuffer.prototype.putBytes = function (e) {
            return (
              (this.data += e), this._optimizeConstructedString(e.length), this
            );
          }),
          (o.ByteStringBuffer.prototype.putString = function (e) {
            return this.putBytes(o.encodeUtf8(e));
          }),
          (o.ByteStringBuffer.prototype.putInt16 = function (e) {
            return this.putBytes(
              String.fromCharCode((e >> 8) & 255) + String.fromCharCode(255 & e)
            );
          }),
          (o.ByteStringBuffer.prototype.putInt24 = function (e) {
            return this.putBytes(
              String.fromCharCode((e >> 16) & 255) +
                String.fromCharCode((e >> 8) & 255) +
                String.fromCharCode(255 & e)
            );
          }),
          (o.ByteStringBuffer.prototype.putInt32 = function (e) {
            return this.putBytes(
              String.fromCharCode((e >> 24) & 255) +
                String.fromCharCode((e >> 16) & 255) +
                String.fromCharCode((e >> 8) & 255) +
                String.fromCharCode(255 & e)
            );
          }),
          (o.ByteStringBuffer.prototype.putInt16Le = function (e) {
            return this.putBytes(
              String.fromCharCode(255 & e) + String.fromCharCode((e >> 8) & 255)
            );
          }),
          (o.ByteStringBuffer.prototype.putInt24Le = function (e) {
            return this.putBytes(
              String.fromCharCode(255 & e) +
                String.fromCharCode((e >> 8) & 255) +
                String.fromCharCode((e >> 16) & 255)
            );
          }),
          (o.ByteStringBuffer.prototype.putInt32Le = function (e) {
            return this.putBytes(
              String.fromCharCode(255 & e) +
                String.fromCharCode((e >> 8) & 255) +
                String.fromCharCode((e >> 16) & 255) +
                String.fromCharCode((e >> 24) & 255)
            );
          }),
          (o.ByteStringBuffer.prototype.putInt = function (e, r) {
            c(r);
            var n = "";
            do (r -= 8), (n += String.fromCharCode((e >> r) & 255));
            while (r > 0);
            return this.putBytes(n);
          }),
          (o.ByteStringBuffer.prototype.putSignedInt = function (e, r) {
            return e < 0 && (e += 2 << (r - 1)), this.putInt(e, r);
          }),
          (o.ByteStringBuffer.prototype.putBuffer = function (e) {
            return this.putBytes(e.getBytes());
          }),
          (o.ByteStringBuffer.prototype.getByte = function () {
            return this.data.charCodeAt(this.read++);
          }),
          (o.ByteStringBuffer.prototype.getInt16 = function () {
            var e =
              (this.data.charCodeAt(this.read) << 8) ^
              this.data.charCodeAt(this.read + 1);
            return (this.read += 2), e;
          }),
          (o.ByteStringBuffer.prototype.getInt24 = function () {
            var e =
              (this.data.charCodeAt(this.read) << 16) ^
              (this.data.charCodeAt(this.read + 1) << 8) ^
              this.data.charCodeAt(this.read + 2);
            return (this.read += 3), e;
          }),
          (o.ByteStringBuffer.prototype.getInt32 = function () {
            var e =
              (this.data.charCodeAt(this.read) << 24) ^
              (this.data.charCodeAt(this.read + 1) << 16) ^
              (this.data.charCodeAt(this.read + 2) << 8) ^
              this.data.charCodeAt(this.read + 3);
            return (this.read += 4), e;
          }),
          (o.ByteStringBuffer.prototype.getInt16Le = function () {
            var e =
              this.data.charCodeAt(this.read) ^
              (this.data.charCodeAt(this.read + 1) << 8);
            return (this.read += 2), e;
          }),
          (o.ByteStringBuffer.prototype.getInt24Le = function () {
            var e =
              this.data.charCodeAt(this.read) ^
              (this.data.charCodeAt(this.read + 1) << 8) ^
              (this.data.charCodeAt(this.read + 2) << 16);
            return (this.read += 3), e;
          }),
          (o.ByteStringBuffer.prototype.getInt32Le = function () {
            var e =
              this.data.charCodeAt(this.read) ^
              (this.data.charCodeAt(this.read + 1) << 8) ^
              (this.data.charCodeAt(this.read + 2) << 16) ^
              (this.data.charCodeAt(this.read + 3) << 24);
            return (this.read += 4), e;
          }),
          (o.ByteStringBuffer.prototype.getInt = function (e) {
            c(e);
            var r = 0;
            do (r = (r << 8) + this.data.charCodeAt(this.read++)), (e -= 8);
            while (e > 0);
            return r;
          }),
          (o.ByteStringBuffer.prototype.getSignedInt = function (e) {
            var r = this.getInt(e),
              n = 2 << (e - 2);
            return r >= n && (r -= n << 1), r;
          }),
          (o.ByteStringBuffer.prototype.getBytes = function (e) {
            var r;
            return (
              e
                ? ((e = Math.min(this.length(), e)),
                  (r = this.data.slice(this.read, this.read + e)),
                  (this.read += e))
                : 0 === e
                ? (r = "")
                : ((r =
                    0 === this.read ? this.data : this.data.slice(this.read)),
                  this.clear()),
              r
            );
          }),
          (o.ByteStringBuffer.prototype.bytes = function (e) {
            return void 0 === e
              ? this.data.slice(this.read)
              : this.data.slice(this.read, this.read + e);
          }),
          (o.ByteStringBuffer.prototype.at = function (e) {
            return this.data.charCodeAt(this.read + e);
          }),
          (o.ByteStringBuffer.prototype.setAt = function (e, r) {
            return (
              (this.data =
                this.data.substr(0, this.read + e) +
                String.fromCharCode(r) +
                this.data.substr(this.read + e + 1)),
              this
            );
          }),
          (o.ByteStringBuffer.prototype.last = function () {
            return this.data.charCodeAt(this.data.length - 1);
          }),
          (o.ByteStringBuffer.prototype.copy = function () {
            var e = o.createBuffer(this.data);
            return (e.read = this.read), e;
          }),
          (o.ByteStringBuffer.prototype.compact = function () {
            return (
              this.read > 0 &&
                ((this.data = this.data.slice(this.read)), (this.read = 0)),
              this
            );
          }),
          (o.ByteStringBuffer.prototype.clear = function () {
            return (this.data = ""), (this.read = 0), this;
          }),
          (o.ByteStringBuffer.prototype.truncate = function (e) {
            var r = Math.max(0, this.length() - e);
            return (
              (this.data = this.data.substr(this.read, r)),
              (this.read = 0),
              this
            );
          }),
          (o.ByteStringBuffer.prototype.toHex = function () {
            for (var e = "", r = this.read; r < this.data.length; ++r) {
              var n = this.data.charCodeAt(r);
              n < 16 && (e += "0"), (e += n.toString(16));
            }
            return e;
          }),
          (o.ByteStringBuffer.prototype.toString = function () {
            return o.decodeUtf8(this.bytes());
          }),
          (o.DataBuffer = function (e, r) {
            (r = r || {}),
              (this.read = r.readOffset || 0),
              (this.growSize = r.growSize || 1024);
            var n = o.isArrayBuffer(e),
              a = o.isArrayBufferView(e);
            if (n || a)
              return (
                (this.data = n
                  ? new DataView(e)
                  : new DataView(e.buffer, e.byteOffset, e.byteLength)),
                void (this.write =
                  "writeOffset" in r ? r.writeOffset : this.data.byteLength)
              );
            (this.data = new DataView(new ArrayBuffer(0))),
              (this.write = 0),
              null != e && this.putBytes(e),
              "writeOffset" in r && (this.write = r.writeOffset);
          }),
          (o.DataBuffer.prototype.length = function () {
            return this.write - this.read;
          }),
          (o.DataBuffer.prototype.isEmpty = function () {
            return 0 >= this.length();
          }),
          (o.DataBuffer.prototype.accommodate = function (e, r) {
            if (this.length() >= e) return this;
            r = Math.max(r || this.growSize, e);
            var n = new Uint8Array(
                this.data.buffer,
                this.data.byteOffset,
                this.data.byteLength
              ),
              a = new Uint8Array(this.length() + r);
            return a.set(n), (this.data = new DataView(a.buffer)), this;
          }),
          (o.DataBuffer.prototype.putByte = function (e) {
            return (
              this.accommodate(1), this.data.setUint8(this.write++, e), this
            );
          }),
          (o.DataBuffer.prototype.fillWithByte = function (e, r) {
            this.accommodate(r);
            for (var n = 0; n < r; ++n) this.data.setUint8(e);
            return this;
          }),
          (o.DataBuffer.prototype.putBytes = function (e, r) {
            if (o.isArrayBufferView(e)) {
              var n,
                a =
                  (s = new Uint8Array(e.buffer, e.byteOffset, e.byteLength))
                    .byteLength - s.byteOffset;
              return (
                this.accommodate(a),
                new Uint8Array(this.data.buffer, this.write).set(s),
                (this.write += a),
                this
              );
            }
            if (o.isArrayBuffer(e)) {
              var s = new Uint8Array(e);
              return (
                this.accommodate(s.byteLength),
                new Uint8Array(this.data.buffer).set(s, this.write),
                (this.write += s.byteLength),
                this
              );
            }
            if (
              e instanceof o.DataBuffer ||
              ("object" == typeof e &&
                "number" == typeof e.read &&
                "number" == typeof e.write &&
                o.isArrayBufferView(e.data))
            )
              return (
                (s = new Uint8Array(e.data.byteLength, e.read, e.length())),
                this.accommodate(s.byteLength),
                new Uint8Array(e.data.byteLength, this.write).set(s),
                (this.write += s.byteLength),
                this
              );
            if (
              (e instanceof o.ByteStringBuffer &&
                ((e = e.data), (r = "binary")),
              (r = r || "binary"),
              "string" == typeof e)
            ) {
              if ("hex" === r)
                return (
                  this.accommodate(Math.ceil(e.length / 2)),
                  (n = new Uint8Array(this.data.buffer, this.write)),
                  (this.write += o.binary.hex.decode(e, n, this.write)),
                  this
                );
              if ("base64" === r)
                return (
                  this.accommodate(3 * Math.ceil(e.length / 4)),
                  (n = new Uint8Array(this.data.buffer, this.write)),
                  (this.write += o.binary.base64.decode(e, n, this.write)),
                  this
                );
              if (
                ("utf8" === r && ((e = o.encodeUtf8(e)), (r = "binary")),
                "binary" === r || "raw" === r)
              )
                return (
                  this.accommodate(e.length),
                  (n = new Uint8Array(this.data.buffer, this.write)),
                  (this.write += o.binary.raw.decode(n)),
                  this
                );
              if ("utf16" === r)
                return (
                  this.accommodate(2 * e.length),
                  (n = new Uint16Array(this.data.buffer, this.write)),
                  (this.write += o.text.utf16.encode(n)),
                  this
                );
              throw Error("Invalid encoding: " + r);
            }
            throw Error("Invalid parameter: " + e);
          }),
          (o.DataBuffer.prototype.putBuffer = function (e) {
            return this.putBytes(e), e.clear(), this;
          }),
          (o.DataBuffer.prototype.putString = function (e) {
            return this.putBytes(e, "utf16");
          }),
          (o.DataBuffer.prototype.putInt16 = function (e) {
            return (
              this.accommodate(2),
              this.data.setInt16(this.write, e),
              (this.write += 2),
              this
            );
          }),
          (o.DataBuffer.prototype.putInt24 = function (e) {
            return (
              this.accommodate(3),
              this.data.setInt16(this.write, (e >> 8) & 65535),
              this.data.setInt8(this.write, (e >> 16) & 255),
              (this.write += 3),
              this
            );
          }),
          (o.DataBuffer.prototype.putInt32 = function (e) {
            return (
              this.accommodate(4),
              this.data.setInt32(this.write, e),
              (this.write += 4),
              this
            );
          }),
          (o.DataBuffer.prototype.putInt16Le = function (e) {
            return (
              this.accommodate(2),
              this.data.setInt16(this.write, e, !0),
              (this.write += 2),
              this
            );
          }),
          (o.DataBuffer.prototype.putInt24Le = function (e) {
            return (
              this.accommodate(3),
              this.data.setInt8(this.write, (e >> 16) & 255),
              this.data.setInt16(this.write, (e >> 8) & 65535, !0),
              (this.write += 3),
              this
            );
          }),
          (o.DataBuffer.prototype.putInt32Le = function (e) {
            return (
              this.accommodate(4),
              this.data.setInt32(this.write, e, !0),
              (this.write += 4),
              this
            );
          }),
          (o.DataBuffer.prototype.putInt = function (e, r) {
            c(r), this.accommodate(r / 8);
            do (r -= 8), this.data.setInt8(this.write++, (e >> r) & 255);
            while (r > 0);
            return this;
          }),
          (o.DataBuffer.prototype.putSignedInt = function (e, r) {
            return (
              c(r),
              this.accommodate(r / 8),
              e < 0 && (e += 2 << (r - 1)),
              this.putInt(e, r)
            );
          }),
          (o.DataBuffer.prototype.getByte = function () {
            return this.data.getInt8(this.read++);
          }),
          (o.DataBuffer.prototype.getInt16 = function () {
            var e = this.data.getInt16(this.read);
            return (this.read += 2), e;
          }),
          (o.DataBuffer.prototype.getInt24 = function () {
            var e =
              (this.data.getInt16(this.read) << 8) ^
              this.data.getInt8(this.read + 2);
            return (this.read += 3), e;
          }),
          (o.DataBuffer.prototype.getInt32 = function () {
            var e = this.data.getInt32(this.read);
            return (this.read += 4), e;
          }),
          (o.DataBuffer.prototype.getInt16Le = function () {
            var e = this.data.getInt16(this.read, !0);
            return (this.read += 2), e;
          }),
          (o.DataBuffer.prototype.getInt24Le = function () {
            var e =
              this.data.getInt8(this.read) ^
              (this.data.getInt16(this.read + 1, !0) << 8);
            return (this.read += 3), e;
          }),
          (o.DataBuffer.prototype.getInt32Le = function () {
            var e = this.data.getInt32(this.read, !0);
            return (this.read += 4), e;
          }),
          (o.DataBuffer.prototype.getInt = function (e) {
            c(e);
            var r = 0;
            do (r = (r << 8) + this.data.getInt8(this.read++)), (e -= 8);
            while (e > 0);
            return r;
          }),
          (o.DataBuffer.prototype.getSignedInt = function (e) {
            var r = this.getInt(e),
              n = 2 << (e - 2);
            return r >= n && (r -= n << 1), r;
          }),
          (o.DataBuffer.prototype.getBytes = function (e) {
            var r;
            return (
              e
                ? ((e = Math.min(this.length(), e)),
                  (r = this.data.slice(this.read, this.read + e)),
                  (this.read += e))
                : 0 === e
                ? (r = "")
                : ((r =
                    0 === this.read ? this.data : this.data.slice(this.read)),
                  this.clear()),
              r
            );
          }),
          (o.DataBuffer.prototype.bytes = function (e) {
            return void 0 === e
              ? this.data.slice(this.read)
              : this.data.slice(this.read, this.read + e);
          }),
          (o.DataBuffer.prototype.at = function (e) {
            return this.data.getUint8(this.read + e);
          }),
          (o.DataBuffer.prototype.setAt = function (e, r) {
            return this.data.setUint8(e, r), this;
          }),
          (o.DataBuffer.prototype.last = function () {
            return this.data.getUint8(this.write - 1);
          }),
          (o.DataBuffer.prototype.copy = function () {
            return new o.DataBuffer(this);
          }),
          (o.DataBuffer.prototype.compact = function () {
            if (this.read > 0) {
              var e = new Uint8Array(this.data.buffer, this.read),
                r = new Uint8Array(e.byteLength);
              r.set(e),
                (this.data = new DataView(r)),
                (this.write -= this.read),
                (this.read = 0);
            }
            return this;
          }),
          (o.DataBuffer.prototype.clear = function () {
            return (
              (this.data = new DataView(new ArrayBuffer(0))),
              (this.read = this.write = 0),
              this
            );
          }),
          (o.DataBuffer.prototype.truncate = function (e) {
            return (
              (this.write = Math.max(0, this.length() - e)),
              (this.read = Math.min(this.read, this.write)),
              this
            );
          }),
          (o.DataBuffer.prototype.toHex = function () {
            for (var e = "", r = this.read; r < this.data.byteLength; ++r) {
              var n = this.data.getUint8(r);
              n < 16 && (e += "0"), (e += n.toString(16));
            }
            return e;
          }),
          (o.DataBuffer.prototype.toString = function (e) {
            var r = new Uint8Array(this.data, this.read, this.length());
            if ("binary" === (e = e || "utf8") || "raw" === e)
              return o.binary.raw.encode(r);
            if ("hex" === e) return o.binary.hex.encode(r);
            if ("base64" === e) return o.binary.base64.encode(r);
            if ("utf8" === e) return o.text.utf8.decode(r);
            if ("utf16" === e) return o.text.utf16.decode(r);
            throw Error("Invalid encoding: " + e);
          }),
          (o.createBuffer = function (e, r) {
            return (
              (r = r || "raw"),
              void 0 !== e && "utf8" === r && (e = o.encodeUtf8(e)),
              new o.ByteBuffer(e)
            );
          }),
          (o.fillString = function (e, r) {
            for (var n = ""; r > 0; )
              1 & r && (n += e), (r >>>= 1) > 0 && (e += e);
            return n;
          }),
          (o.xorBytes = function (e, r, n) {
            for (var a = "", s = "", o = "", c = 0, u = 0; n > 0; --n, ++c)
              (s = e.charCodeAt(c) ^ r.charCodeAt(c)),
                u >= 10 && ((a += o), (o = ""), (u = 0)),
                (o += String.fromCharCode(s)),
                ++u;
            return a + o;
          }),
          (o.hexToBytes = function (e) {
            var r = "",
              n = 0;
            for (
              !0 & e.length &&
              ((n = 1), (r += String.fromCharCode(parseInt(e[0], 16))));
              n < e.length;
              n += 2
            )
              r += String.fromCharCode(parseInt(e.substr(n, 2), 16));
            return r;
          }),
          (o.bytesToHex = function (e) {
            return o.createBuffer(e).toHex();
          }),
          (o.int32ToBytes = function (e) {
            return (
              String.fromCharCode((e >> 24) & 255) +
              String.fromCharCode((e >> 16) & 255) +
              String.fromCharCode((e >> 8) & 255) +
              String.fromCharCode(255 & e)
            );
          });
        var l =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
          p = [
            62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
            -1, 64, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
            42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
          ],
          f = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        (o.encode64 = function (e, r) {
          for (var n, a, s, o = "", c = "", u = 0; u < e.length; )
            (n = e.charCodeAt(u++)),
              (a = e.charCodeAt(u++)),
              (s = e.charCodeAt(u++)),
              (o += l.charAt(n >> 2)),
              (o += l.charAt(((3 & n) << 4) | (a >> 4))),
              isNaN(a)
                ? (o += "==")
                : ((o += l.charAt(((15 & a) << 2) | (s >> 6))),
                  (o += isNaN(s) ? "=" : l.charAt(63 & s))),
              r &&
                o.length > r &&
                ((c += o.substr(0, r) + "\r\n"), (o = o.substr(r)));
          return c + o;
        }),
          (o.decode64 = function (e) {
            e = e.replace(/[^A-Za-z0-9\+\/\=]/g, "");
            for (var r, n, a, s, o = "", c = 0; c < e.length; )
              (r = p[e.charCodeAt(c++) - 43]),
                (n = p[e.charCodeAt(c++) - 43]),
                (a = p[e.charCodeAt(c++) - 43]),
                (s = p[e.charCodeAt(c++) - 43]),
                (o += String.fromCharCode((r << 2) | (n >> 4))),
                64 !== a &&
                  ((o += String.fromCharCode(((15 & n) << 4) | (a >> 2))),
                  64 !== s && (o += String.fromCharCode(((3 & a) << 6) | s)));
            return o;
          }),
          (o.encodeUtf8 = function (e) {
            return unescape(encodeURIComponent(e));
          }),
          (o.decodeUtf8 = function (e) {
            return decodeURIComponent(escape(e));
          }),
          (o.binary = {
            raw: {},
            hex: {},
            base64: {},
            base58: {},
            baseN: { encode: s.encode, decode: s.decode },
          }),
          (o.binary.raw.encode = function (e) {
            return String.fromCharCode.apply(null, e);
          }),
          (o.binary.raw.decode = function (e, r, n) {
            var a = r;
            a || (a = new Uint8Array(e.length));
            for (var s = (n = n || 0), o = 0; o < e.length; ++o)
              a[s++] = e.charCodeAt(o);
            return r ? s - n : a;
          }),
          (o.binary.hex.encode = o.bytesToHex),
          (o.binary.hex.decode = function (e, r, n) {
            var a = r;
            a || (a = new Uint8Array(Math.ceil(e.length / 2)));
            var s = 0,
              o = (n = n || 0);
            for (
              1 & e.length && ((s = 1), (a[o++] = parseInt(e[0], 16)));
              s < e.length;
              s += 2
            )
              a[o++] = parseInt(e.substr(s, 2), 16);
            return r ? o - n : a;
          }),
          (o.binary.base64.encode = function (e, r) {
            for (var n, a, s, o = "", c = "", u = 0; u < e.byteLength; )
              (n = e[u++]),
                (a = e[u++]),
                (s = e[u++]),
                (o += l.charAt(n >> 2)),
                (o += l.charAt(((3 & n) << 4) | (a >> 4))),
                isNaN(a)
                  ? (o += "==")
                  : ((o += l.charAt(((15 & a) << 2) | (s >> 6))),
                    (o += isNaN(s) ? "=" : l.charAt(63 & s))),
                r &&
                  o.length > r &&
                  ((c += o.substr(0, r) + "\r\n"), (o = o.substr(r)));
            return c + o;
          }),
          (o.binary.base64.decode = function (e, r, n) {
            var a,
              s,
              o,
              c,
              u = r;
            u || (u = new Uint8Array(3 * Math.ceil(e.length / 4))),
              (e = e.replace(/[^A-Za-z0-9\+\/\=]/g, ""));
            for (var l = 0, f = (n = n || 0); l < e.length; )
              (a = p[e.charCodeAt(l++) - 43]),
                (s = p[e.charCodeAt(l++) - 43]),
                (o = p[e.charCodeAt(l++) - 43]),
                (c = p[e.charCodeAt(l++) - 43]),
                (u[f++] = (a << 2) | (s >> 4)),
                64 !== o &&
                  ((u[f++] = ((15 & s) << 4) | (o >> 2)),
                  64 !== c && (u[f++] = ((3 & o) << 6) | c));
            return r ? f - n : u.subarray(0, f);
          }),
          (o.binary.base58.encode = function (e, r) {
            return o.binary.baseN.encode(e, f, r);
          }),
          (o.binary.base58.decode = function (e, r) {
            return o.binary.baseN.decode(e, f, r);
          }),
          (o.text = { utf8: {}, utf16: {} }),
          (o.text.utf8.encode = function (e, r, n) {
            e = o.encodeUtf8(e);
            var a = r;
            a || (a = new Uint8Array(e.length));
            for (var s = (n = n || 0), c = 0; c < e.length; ++c)
              a[s++] = e.charCodeAt(c);
            return r ? s - n : a;
          }),
          (o.text.utf8.decode = function (e) {
            return o.decodeUtf8(String.fromCharCode.apply(null, e));
          }),
          (o.text.utf16.encode = function (e, r, n) {
            var a = r;
            a || (a = new Uint8Array(2 * e.length));
            for (
              var s = new Uint16Array(a.buffer), o = (n = n || 0), c = n, u = 0;
              u < e.length;
              ++u
            )
              (s[c++] = e.charCodeAt(u)), (o += 2);
            return r ? o - n : a;
          }),
          (o.text.utf16.decode = function (e) {
            return String.fromCharCode.apply(null, new Uint16Array(e.buffer));
          }),
          (o.deflate = function (e, r, n) {
            if (((r = o.decode64(e.deflate(o.encode64(r)).rval)), n)) {
              var a = 2;
              32 & r.charCodeAt(1) && (a = 6),
                (r = r.substring(a, r.length - 4));
            }
            return r;
          }),
          (o.inflate = function (e, r, n) {
            var a = e.inflate(o.encode64(r)).rval;
            return null === a ? null : o.decode64(a);
          });
        var h = function (e, r, n) {
            if (!e) throw Error("WebStorage not available.");
            if (
              (null === n
                ? (a = e.removeItem(r))
                : ((n = o.encode64(JSON.stringify(n))), (a = e.setItem(r, n))),
              void 0 !== a && !0 !== a.rval)
            ) {
              var a,
                s = Error(a.error.message);
              throw ((s.id = a.error.id), (s.name = a.error.name), s);
            }
          },
          d = function (e, r) {
            if (!e) throw Error("WebStorage not available.");
            var n = e.getItem(r);
            if (e.init) {
              if (null === n.rval) {
                if (n.error) {
                  var a = Error(n.error.message);
                  throw ((a.id = n.error.id), (a.name = n.error.name), a);
                }
                n = null;
              } else n = n.rval;
            }
            return null !== n && (n = JSON.parse(o.decode64(n))), n;
          },
          _ = function (e, r, n, a) {
            var s = d(e, r);
            null === s && (s = {}), (s[n] = a), h(e, r, s);
          },
          $ = function (e, r, n) {
            var a = d(e, r);
            return null !== a && (a = n in a ? a[n] : null), a;
          },
          y = function (e, r, n) {
            var a = d(e, r);
            if (null !== a && n in a) {
              delete a[n];
              var s = !0;
              for (var o in a) {
                s = !1;
                break;
              }
              s && (a = null), h(e, r, a);
            }
          },
          g = function (e, r) {
            h(e, r, null);
          },
          v = function (e, r, n) {
            var a,
              s = null;
            void 0 === n && (n = ["web", "flash"]);
            var o = !1,
              c = null;
            for (var u in n) {
              a = n[u];
              try {
                if ("flash" === a || "both" === a) {
                  if (null === r[0])
                    throw Error("Flash local storage not available.");
                  (s = e.apply(this, r)), (o = "flash" === a);
                }
                ("web" !== a && "both" !== a) ||
                  ((r[0] = localStorage), (s = e.apply(this, r)), (o = !0));
              } catch (l) {
                c = l;
              }
              if (o) break;
            }
            if (!o) throw c;
            return s;
          };
        (o.setItem = function (e, r, n, a, s) {
          v(_, arguments, s);
        }),
          (o.getItem = function (e, r, n, a) {
            return v($, arguments, a);
          }),
          (o.removeItem = function (e, r, n, a) {
            v(y, arguments, a);
          }),
          (o.clearItems = function (e, r, n) {
            v(g, arguments, n);
          }),
          (o.isEmpty = function (e) {
            for (var r in e) if (e.hasOwnProperty(r)) return !1;
            return !0;
          }),
          (o.format = function (e) {
            for (var r, n, a = /%./g, s = 0, o = [], c = 0; (r = a.exec(e)); ) {
              (n = e.substring(c, a.lastIndex - 2)).length > 0 && o.push(n),
                (c = a.lastIndex);
              var u = r[0][1];
              switch (u) {
                case "s":
                case "o":
                  s < arguments.length
                    ? o.push(arguments[1 + s++])
                    : o.push("<?>");
                  break;
                case "%":
                  o.push("%");
                  break;
                default:
                  o.push("<%" + u + "?>");
              }
            }
            return o.push(e.substring(c)), o.join("");
          }),
          (o.formatNumber = function (e, r, n, a) {
            var s = e,
              o = isNaN((r = Math.abs(r))) ? 2 : r,
              c = void 0 === a ? "." : a,
              u = s < 0 ? "-" : "",
              l = parseInt((s = Math.abs(+s || 0).toFixed(o)), 10) + "",
              p = l.length > 3 ? l.length % 3 : 0;
            return (
              u +
              (p ? l.substr(0, p) + c : "") +
              l.substr(p).replace(/(\d{3})(?=\d)/g, "$1" + c) +
              (o
                ? (void 0 === n ? "," : n) +
                  Math.abs(s - l)
                    .toFixed(o)
                    .slice(2)
                : "")
            );
          }),
          (o.formatSize = function (e) {
            return (e =
              e >= 1073741824
                ? o.formatNumber(e / 1073741824, 2, ".", "") + " GiB"
                : e >= 1048576
                ? o.formatNumber(e / 1048576, 2, ".", "") + " MiB"
                : e >= 1024
                ? o.formatNumber(e / 1024, 0) + " KiB"
                : o.formatNumber(e, 0) + " bytes");
          }),
          (o.bytesFromIP = function (e) {
            return -1 !== e.indexOf(".")
              ? o.bytesFromIPv4(e)
              : -1 !== e.indexOf(":")
              ? o.bytesFromIPv6(e)
              : null;
          }),
          (o.bytesFromIPv4 = function (e) {
            if (4 !== (e = e.split(".")).length) return null;
            for (var r = o.createBuffer(), n = 0; n < e.length; ++n) {
              var a = parseInt(e[n], 10);
              if (isNaN(a)) return null;
              r.putByte(a);
            }
            return r.getBytes();
          }),
          (o.bytesFromIPv6 = function (e) {
            for (
              var r = 0,
                n =
                  2 *
                  (8 -
                    (e = e.split(":").filter(function (e) {
                      return 0 === e.length && ++r, !0;
                    })).length +
                    r),
                a = o.createBuffer(),
                s = 0;
              s < 8;
              ++s
            )
              if (e[s] && 0 !== e[s].length) {
                var c = o.hexToBytes(e[s]);
                c.length < 2 && a.putByte(0), a.putBytes(c);
              } else a.fillWithByte(0, n), (n = 0);
            return a.getBytes();
          }),
          (o.bytesToIP = function (e) {
            return 4 === e.length
              ? o.bytesToIPv4(e)
              : 16 === e.length
              ? o.bytesToIPv6(e)
              : null;
          }),
          (o.bytesToIPv4 = function (e) {
            if (4 !== e.length) return null;
            for (var r = [], n = 0; n < e.length; ++n) r.push(e.charCodeAt(n));
            return r.join(".");
          }),
          (o.bytesToIPv6 = function (e) {
            if (16 !== e.length) return null;
            for (var r = [], n = [], a = 0, s = 0; s < e.length; s += 2) {
              for (
                var c = o.bytesToHex(e[s] + e[s + 1]);
                "0" === c[0] && "0" !== c;

              )
                c = c.substr(1);
              if ("0" === c) {
                var u = n[n.length - 1],
                  l = r.length;
                u && l === u.end + 1
                  ? ((u.end = l),
                    u.end - u.start > n[a].end - n[a].start &&
                      (a = n.length - 1))
                  : n.push({ start: l, end: l });
              }
              r.push(c);
            }
            if (n.length > 0) {
              var p = n[a];
              p.end - p.start > 0 &&
                (r.splice(p.start, p.end - p.start + 1, ""),
                0 === p.start && r.unshift(""),
                7 === p.end && r.push(""));
            }
            return r.join(":");
          }),
          (o.estimateCores = function (e, r) {
            if (
              ("function" == typeof e && ((r = e), (e = {})),
              (e = e || {}),
              "cores" in o && !e.update)
            )
              return r(null, o.cores);
            if (
              "undefined" != typeof navigator &&
              "hardwareConcurrency" in navigator &&
              navigator.hardwareConcurrency > 0
            )
              return (
                (o.cores = navigator.hardwareConcurrency), r(null, o.cores)
              );
            if ("undefined" == typeof Worker)
              return (o.cores = 1), r(null, o.cores);
            if ("undefined" == typeof Blob)
              return (o.cores = 2), r(null, o.cores);
            var n = URL.createObjectURL(
              new Blob(
                [
                  "(",
                  function () {
                    self.addEventListener("message", function (e) {
                      for (var r = Date.now(), n = r + 4; Date.now() < n; );
                      self.postMessage({ st: r, et: n });
                    });
                  }.toString(),
                  ")()",
                ],
                { type: "application/javascript" }
              )
            );
            !(function e(a, s, c) {
              if (0 === s) {
                var u = Math.floor(
                  a.reduce(function (e, r) {
                    return e + r;
                  }, 0) / a.length
                );
                return (
                  (o.cores = Math.max(1, u)),
                  URL.revokeObjectURL(n),
                  r(null, o.cores)
                );
              }
              !(function (e, r) {
                for (var a = [], s = [], o = 0; o < e; ++o) {
                  var c = new Worker(n);
                  c.addEventListener("message", function (n) {
                    if ((s.push(n.data), s.length === e)) {
                      for (var o = 0; o < e; ++o) a[o].terminate();
                      r(null, s);
                    }
                  }),
                    a.push(c);
                }
                for (o = 0; o < e; ++o) a[o].postMessage(o);
              })(c, function (r, n) {
                a.push(
                  (function (e, r) {
                    for (var n = [], a = 0; a < e; ++a)
                      for (var s = r[a], o = (n[a] = []), c = 0; c < e; ++c)
                        if (a !== c) {
                          var u = r[c];
                          ((s.st > u.st && s.st < u.et) ||
                            (u.st > s.st && u.st < s.et)) &&
                            o.push(c);
                        }
                    return n.reduce(function (e, r) {
                      return Math.max(e, r.length);
                    }, 0);
                  })(c, n)
                ),
                  e(a, s - 1, c);
              });
            })([], 5, 16);
          });
      }).call(this, n(34));
    },
    function (e, r, n) {
      var a = n(0);
      n(5),
        n(23),
        n(24),
        n(1),
        a.random && a.random.getBytes
          ? (e.exports = a.random)
          : (function (r) {
              var n = {},
                s = [, , , ,],
                o = a.util.createBuffer();
              function c() {
                var e = a.prng.create(n);
                return (
                  (e.getBytes = function (r, n) {
                    return e.generate(r, n);
                  }),
                  (e.getBytesSync = function (r) {
                    return e.generate(r);
                  }),
                  e
                );
              }
              (n.formatKey = function (e) {
                var r = a.util.createBuffer(e);
                return (
                  ((e = [, , , ,])[0] = r.getInt32()),
                  (e[1] = r.getInt32()),
                  (e[2] = r.getInt32()),
                  (e[3] = r.getInt32()),
                  a.aes._expandKey(e, !1)
                );
              }),
                (n.formatSeed = function (e) {
                  var r = a.util.createBuffer(e);
                  return (
                    ((e = [, , , ,])[0] = r.getInt32()),
                    (e[1] = r.getInt32()),
                    (e[2] = r.getInt32()),
                    (e[3] = r.getInt32()),
                    e
                  );
                }),
                (n.cipher = function (e, r) {
                  return (
                    a.aes._updateBlock(e, r, s, !1),
                    o.putInt32(s[0]),
                    o.putInt32(s[1]),
                    o.putInt32(s[2]),
                    o.putInt32(s[3]),
                    o.getBytes()
                  );
                }),
                (n.increment = function (e) {
                  return ++e[3], e;
                }),
                (n.md = a.md.sha256);
              var u = c(),
                l = null,
                p = a.util.globalScope,
                f = p.crypto || p.msCrypto;
              if (
                (f &&
                  f.getRandomValues &&
                  (l = function (e) {
                    return f.getRandomValues(e);
                  }),
                !a.options.usePureJavaScript && a.util.isNodejs,
                a.random)
              )
                for (var h in u) a.random[h] = u[h];
              else a.random = u;
              (a.random.createInstance = c), (e.exports = a.random);
            })("undefined" != typeof jQuery ? jQuery : null);
    },
    function (e, r, n) {
      var a = n(0);
      n(1), n(6);
      var s = (e.exports = a.asn1 = a.asn1 || {});
      function o(e, r, n) {
        if (n > r) {
          var a = Error("Too few bytes to parse DER.");
          throw (
            ((a.available = e.length()),
            (a.remaining = r),
            (a.requested = n),
            a)
          );
        }
      }
      (s.Class = {
        UNIVERSAL: 0,
        APPLICATION: 64,
        CONTEXT_SPECIFIC: 128,
        PRIVATE: 192,
      }),
        (s.Type = {
          NONE: 0,
          BOOLEAN: 1,
          INTEGER: 2,
          BITSTRING: 3,
          OCTETSTRING: 4,
          NULL: 5,
          OID: 6,
          ODESC: 7,
          EXTERNAL: 8,
          REAL: 9,
          ENUMERATED: 10,
          EMBEDDED: 11,
          UTF8: 12,
          ROID: 13,
          SEQUENCE: 16,
          SET: 17,
          PRINTABLESTRING: 19,
          IA5STRING: 22,
          UTCTIME: 23,
          GENERALIZEDTIME: 24,
          BMPSTRING: 30,
        }),
        (s.create = function (e, r, n, o, c) {
          if (a.util.isArray(o)) {
            for (var u = [], l = 0; l < o.length; ++l)
              void 0 !== o[l] && u.push(o[l]);
            o = u;
          }
          var p = {
            tagClass: e,
            type: r,
            constructed: n,
            composed: n || a.util.isArray(o),
            value: o,
          };
          return (
            c &&
              "bitStringContents" in c &&
              ((p.bitStringContents = c.bitStringContents),
              (p.original = s.copy(p))),
            p
          );
        }),
        (s.copy = function (e, r) {
          var n;
          if (a.util.isArray(e)) {
            n = [];
            for (var o = 0; o < e.length; ++o) n.push(s.copy(e[o], r));
            return n;
          }
          return "string" == typeof e
            ? e
            : ((n = {
                tagClass: e.tagClass,
                type: e.type,
                constructed: e.constructed,
                composed: e.composed,
                value: s.copy(e.value, r),
              }),
              r &&
                !r.excludeBitStringContents &&
                (n.bitStringContents = e.bitStringContents),
              n);
        }),
        (s.equals = function (e, r, n) {
          if (a.util.isArray(e)) {
            if (!a.util.isArray(r) || e.length !== r.length) return !1;
            for (var o = 0; o < e.length; ++o)
              if (!s.equals(e[o], r[o])) return !1;
            return !0;
          }
          if (typeof e != typeof r) return !1;
          if ("string" == typeof e) return e === r;
          var c =
            e.tagClass === r.tagClass &&
            e.type === r.type &&
            e.constructed === r.constructed &&
            e.composed === r.composed &&
            s.equals(e.value, r.value);
          return (
            n &&
              n.includeBitStringContents &&
              (c = c && e.bitStringContents === r.bitStringContents),
            c
          );
        }),
        (s.getBerValueLength = function (e) {
          var r = e.getByte();
          if (128 !== r) return 128 & r ? e.getInt((127 & r) << 3) : r;
        }),
        (s.fromDer = function (e, r) {
          void 0 === r &&
            (r = { strict: !0, parseAllBytes: !0, decodeBitStrings: !0 }),
            "boolean" == typeof r &&
              (r = { strict: r, parseAllBytes: !0, decodeBitStrings: !0 }),
            "strict" in r || (r.strict = !0),
            "parseAllBytes" in r || (r.parseAllBytes = !0),
            "decodeBitStrings" in r || (r.decodeBitStrings = !0),
            "string" == typeof e && (e = a.util.createBuffer(e));
          var n = e.length(),
            c = (function e(r, n, a, c) {
              o(r, n, 2);
              var u = r.getByte();
              n--;
              var l = 192 & u,
                p = 31 & u;
              f = r.length();
              var f,
                h,
                d,
                _ = (function (e, r) {
                  var n,
                    a = e.getByte();
                  if ((r--, 128 !== a)) {
                    if (128 & a) {
                      var s = 127 & a;
                      o(e, r, s), (n = e.getInt(s << 3));
                    } else n = a;
                    if (n < 0) throw Error("Negative length: " + n);
                    return n;
                  }
                })(r, n);
              if (((n -= f - r.length()), void 0 !== _ && _ > n)) {
                if (c.strict) {
                  var $ = Error("Too few bytes to read ASN.1 value.");
                  throw (
                    (($.available = r.length()),
                    ($.remaining = n),
                    ($.requested = _),
                    $)
                  );
                }
                _ = n;
              }
              var y = 32 == (32 & u);
              if (y) {
                if (((h = []), void 0 === _))
                  for (;;) {
                    if (
                      (o(r, n, 2), r.bytes(2) === String.fromCharCode(0, 0))
                    ) {
                      r.getBytes(2), (n -= 2);
                      break;
                    }
                    (f = r.length()),
                      h.push(e(r, n, a + 1, c)),
                      (n -= f - r.length());
                  }
                else
                  for (; _ > 0; )
                    (f = r.length()),
                      h.push(e(r, _, a + 1, c)),
                      (n -= f - r.length()),
                      (_ -= f - r.length());
              }
              if (
                (void 0 === h &&
                  l === s.Class.UNIVERSAL &&
                  p === s.Type.BITSTRING &&
                  (d = r.bytes(_)),
                void 0 === h &&
                  c.decodeBitStrings &&
                  l === s.Class.UNIVERSAL &&
                  p === s.Type.BITSTRING &&
                  _ > 1)
              ) {
                var g = r.read,
                  v = n,
                  m = 0;
                if (
                  (p === s.Type.BITSTRING &&
                    (o(r, n, 1), (m = r.getByte()), n--),
                  0 === m)
                )
                  try {
                    f = r.length();
                    var C = e(r, n, a + 1, {
                        strict: !0,
                        decodeBitStrings: !0,
                      }),
                      E = f - r.length();
                    (n -= E), p == s.Type.BITSTRING && E++;
                    var S = C.tagClass;
                    E !== _ ||
                      (S !== s.Class.UNIVERSAL &&
                        S !== s.Class.CONTEXT_SPECIFIC) ||
                      (h = [C]);
                  } catch (T) {}
                void 0 === h && ((r.read = g), (n = v));
              }
              if (void 0 === h) {
                if (void 0 === _) {
                  if (c.strict)
                    throw Error(
                      "Non-constructed ASN.1 object of indefinite length."
                    );
                  _ = n;
                }
                if (p === s.Type.BMPSTRING)
                  for (h = ""; _ > 0; _ -= 2)
                    o(r, n, 2),
                      (h += String.fromCharCode(r.getInt16())),
                      (n -= 2);
                else (h = r.getBytes(_)), (n -= _);
              }
              var B = void 0 === d ? null : { bitStringContents: d };
              return s.create(l, p, y, h, B);
            })(e, e.length(), 0, r);
          if (r.parseAllBytes && 0 !== e.length()) {
            var u = Error("Unparsed DER bytes remain after ASN.1 parsing.");
            throw ((u.byteCount = n), (u.remaining = e.length()), u);
          }
          return c;
        }),
        (s.toDer = function (e) {
          var r = a.util.createBuffer(),
            n = e.tagClass | e.type,
            o = a.util.createBuffer(),
            c = !1;
          if (
            ("bitStringContents" in e &&
              ((c = !0), e.original && (c = s.equals(e, e.original))),
            c)
          )
            o.putBytes(e.bitStringContents);
          else if (e.composed) {
            e.constructed ? (n |= 32) : o.putByte(0);
            for (var u = 0; u < e.value.length; ++u)
              void 0 !== e.value[u] && o.putBuffer(s.toDer(e.value[u]));
          } else if (e.type === s.Type.BMPSTRING)
            for (u = 0; u < e.value.length; ++u)
              o.putInt16(e.value.charCodeAt(u));
          else
            e.type === s.Type.INTEGER &&
            e.value.length > 1 &&
            ((0 === e.value.charCodeAt(0) &&
              0 == (128 & e.value.charCodeAt(1))) ||
              (255 === e.value.charCodeAt(0) &&
                128 == (128 & e.value.charCodeAt(1))))
              ? o.putBytes(e.value.substr(1))
              : o.putBytes(e.value);
          if ((r.putByte(n), 127 >= o.length())) r.putByte(127 & o.length());
          else {
            var l = o.length(),
              p = "";
            do (p += String.fromCharCode(255 & l)), (l >>>= 8);
            while (l > 0);
            for (r.putByte(128 | p.length), u = p.length - 1; u >= 0; --u)
              r.putByte(p.charCodeAt(u));
          }
          return r.putBuffer(o), r;
        }),
        (s.oidToDer = function (e) {
          var r,
            n,
            s,
            o,
            c = e.split("."),
            u = a.util.createBuffer();
          u.putByte(40 * parseInt(c[0], 10) + parseInt(c[1], 10));
          for (var l = 2; l < c.length; ++l) {
            (r = !0), (n = []), (s = parseInt(c[l], 10));
            do (o = 127 & s), (s >>>= 7), r || (o |= 128), n.push(o), (r = !1);
            while (s > 0);
            for (var p = n.length - 1; p >= 0; --p) u.putByte(n[p]);
          }
          return u;
        }),
        (s.derToOid = function (e) {
          "string" == typeof e && (e = a.util.createBuffer(e));
          var r,
            n = e.getByte();
          r = Math.floor(n / 40) + "." + (n % 40);
          for (var s = 0; e.length() > 0; )
            (s <<= 7),
              128 & (n = e.getByte())
                ? (s += 127 & n)
                : ((r += "." + (s + n)), (s = 0));
          return r;
        }),
        (s.utcTimeToDate = function (e) {
          var r = new Date(),
            n = parseInt(e.substr(0, 2), 10);
          n = n >= 50 ? 1900 + n : 2e3 + n;
          var a = parseInt(e.substr(2, 2), 10) - 1,
            s = parseInt(e.substr(4, 2), 10),
            o = parseInt(e.substr(6, 2), 10),
            c = parseInt(e.substr(8, 2), 10),
            u = 0;
          if (e.length > 11) {
            var l = e.charAt(10),
              p = 10;
            "+" !== l &&
              "-" !== l &&
              ((u = parseInt(e.substr(10, 2), 10)), (p += 2));
          }
          if (
            (r.setUTCFullYear(n, a, s),
            r.setUTCHours(o, c, u, 0),
            p && ("+" === (l = e.charAt(p)) || "-" === l))
          ) {
            var f =
              60 * parseInt(e.substr(p + 1, 2), 10) +
              parseInt(e.substr(p + 4, 2), 10);
            (f *= 6e4), "+" === l ? r.setTime(+r - f) : r.setTime(+r + f);
          }
          return r;
        }),
        (s.generalizedTimeToDate = function (e) {
          var r = new Date(),
            n = parseInt(e.substr(0, 4), 10),
            a = parseInt(e.substr(4, 2), 10) - 1,
            s = parseInt(e.substr(6, 2), 10),
            o = parseInt(e.substr(8, 2), 10),
            c = parseInt(e.substr(10, 2), 10),
            u = parseInt(e.substr(12, 2), 10),
            l = 0,
            p = 0,
            f = !1;
          "Z" === e.charAt(e.length - 1) && (f = !0);
          var h = e.length - 5,
            d = e.charAt(h);
          return (
            ("+" !== d && "-" !== d) ||
              ((p =
                60 * parseInt(e.substr(h + 1, 2), 10) +
                parseInt(e.substr(h + 4, 2), 10)),
              (p *= 6e4),
              "+" === d && (p *= -1),
              (f = !0)),
            "." === e.charAt(14) && (l = 1e3 * parseFloat(e.substr(14), 10)),
            f
              ? (r.setUTCFullYear(n, a, s),
                r.setUTCHours(o, c, u, l),
                r.setTime(+r + p))
              : (r.setFullYear(n, a, s), r.setHours(o, c, u, l)),
            r
          );
        }),
        (s.dateToUtcTime = function (e) {
          if ("string" == typeof e) return e;
          var r = "",
            n = [];
          n.push(("" + e.getUTCFullYear()).substr(2)),
            n.push("" + (e.getUTCMonth() + 1)),
            n.push("" + e.getUTCDate()),
            n.push("" + e.getUTCHours()),
            n.push("" + e.getUTCMinutes()),
            n.push("" + e.getUTCSeconds());
          for (var a = 0; a < n.length; ++a)
            n[a].length < 2 && (r += "0"), (r += n[a]);
          return r + "Z";
        }),
        (s.dateToGeneralizedTime = function (e) {
          if ("string" == typeof e) return e;
          var r = "",
            n = [];
          n.push("" + e.getUTCFullYear()),
            n.push("" + (e.getUTCMonth() + 1)),
            n.push("" + e.getUTCDate()),
            n.push("" + e.getUTCHours()),
            n.push("" + e.getUTCMinutes()),
            n.push("" + e.getUTCSeconds());
          for (var a = 0; a < n.length; ++a)
            n[a].length < 2 && (r += "0"), (r += n[a]);
          return r + "Z";
        }),
        (s.integerToDer = function (e) {
          var r = a.util.createBuffer();
          if (e >= -128 && e < 128) return r.putSignedInt(e, 8);
          if (e >= -32768 && e < 32768) return r.putSignedInt(e, 16);
          if (e >= -8388608 && e < 8388608) return r.putSignedInt(e, 24);
          if (e >= -2147483648 && e < 2147483648) return r.putSignedInt(e, 32);
          var n = Error("Integer too large; max is 32-bits.");
          throw ((n.integer = e), n);
        }),
        (s.derToInteger = function (e) {
          "string" == typeof e && (e = a.util.createBuffer(e));
          var r = 8 * e.length();
          if (r > 32) throw Error("Integer too large; max is 32-bits.");
          return e.getSignedInt(r);
        }),
        (s.validate = function (e, r, n, o) {
          var c = !1;
          if (
            (e.tagClass !== r.tagClass && void 0 !== r.tagClass) ||
            (e.type !== r.type && void 0 !== r.type)
          )
            o &&
              (e.tagClass !== r.tagClass &&
                o.push(
                  "[" +
                    r.name +
                    '] Expected tag class "' +
                    r.tagClass +
                    '", got "' +
                    e.tagClass +
                    '"'
                ),
              e.type !== r.type &&
                o.push(
                  "[" +
                    r.name +
                    '] Expected type "' +
                    r.type +
                    '", got "' +
                    e.type +
                    '"'
                ));
          else if (
            e.constructed === r.constructed ||
            void 0 === r.constructed
          ) {
            if (((c = !0), r.value && a.util.isArray(r.value)))
              for (var u = 0, l = 0; c && l < r.value.length; ++l)
                (c = r.value[l].optional || !1),
                  e.value[u] &&
                    ((c = s.validate(e.value[u], r.value[l], n, o))
                      ? ++u
                      : r.value[l].optional && (c = !0)),
                  !c &&
                    o &&
                    o.push(
                      "[" +
                        r.name +
                        '] Tag class "' +
                        r.tagClass +
                        '", type "' +
                        r.type +
                        '" expected value length "' +
                        r.value.length +
                        '", got "' +
                        e.value.length +
                        '"'
                    );
            if (
              c &&
              n &&
              (r.capture && (n[r.capture] = e.value),
              r.captureAsn1 && (n[r.captureAsn1] = e),
              r.captureBitStringContents &&
                "bitStringContents" in e &&
                (n[r.captureBitStringContents] = e.bitStringContents),
              r.captureBitStringValue && "bitStringContents" in e)
            ) {
              if (e.bitStringContents.length < 2)
                n[r.captureBitStringValue] = "";
              else {
                if (0 !== e.bitStringContents.charCodeAt(0))
                  throw Error(
                    "captureBitStringValue only supported for zero unused bits"
                  );
                n[r.captureBitStringValue] = e.bitStringContents.slice(1);
              }
            }
          } else
            o &&
              o.push(
                "[" +
                  r.name +
                  '] Expected constructed "' +
                  r.constructed +
                  '", got "' +
                  e.constructed +
                  '"'
              );
          return c;
        });
      var c = /[^\\u0000-\\u00ff]/;
      s.prettyPrint = function (e, r, n) {
        var o = "";
        (n = n || 2), (r = r || 0) > 0 && (o += "\n");
        for (var u = "", l = 0; l < r * n; ++l) u += " ";
        switch (((o += u + "Tag: "), e.tagClass)) {
          case s.Class.UNIVERSAL:
            o += "Universal:";
            break;
          case s.Class.APPLICATION:
            o += "Application:";
            break;
          case s.Class.CONTEXT_SPECIFIC:
            o += "Context-Specific:";
            break;
          case s.Class.PRIVATE:
            o += "Private:";
        }
        if (e.tagClass === s.Class.UNIVERSAL)
          switch (((o += e.type), e.type)) {
            case s.Type.NONE:
              o += " (None)";
              break;
            case s.Type.BOOLEAN:
              o += " (Boolean)";
              break;
            case s.Type.INTEGER:
              o += " (Integer)";
              break;
            case s.Type.BITSTRING:
              o += " (Bit string)";
              break;
            case s.Type.OCTETSTRING:
              o += " (Octet string)";
              break;
            case s.Type.NULL:
              o += " (Null)";
              break;
            case s.Type.OID:
              o += " (Object Identifier)";
              break;
            case s.Type.ODESC:
              o += " (Object Descriptor)";
              break;
            case s.Type.EXTERNAL:
              o += " (External or Instance of)";
              break;
            case s.Type.REAL:
              o += " (Real)";
              break;
            case s.Type.ENUMERATED:
              o += " (Enumerated)";
              break;
            case s.Type.EMBEDDED:
              o += " (Embedded PDV)";
              break;
            case s.Type.UTF8:
              o += " (UTF8)";
              break;
            case s.Type.ROID:
              o += " (Relative Object Identifier)";
              break;
            case s.Type.SEQUENCE:
              o += " (Sequence)";
              break;
            case s.Type.SET:
              o += " (Set)";
              break;
            case s.Type.PRINTABLESTRING:
              o += " (Printable String)";
              break;
            case s.Type.IA5String:
              o += " (IA5String (ASCII))";
              break;
            case s.Type.UTCTIME:
              o += " (UTC time)";
              break;
            case s.Type.GENERALIZEDTIME:
              o += " (Generalized time)";
              break;
            case s.Type.BMPSTRING:
              o += " (BMP String)";
          }
        else o += e.type;
        if (
          ((o += "\n"),
          (o += u + "Constructed: " + e.constructed + "\n"),
          e.composed)
        ) {
          var p = 0,
            f = "";
          for (l = 0; l < e.value.length; ++l)
            void 0 !== e.value[l] &&
              ((p += 1),
              (f += s.prettyPrint(e.value[l], r + 1, n)),
              l + 1 < e.value.length && (f += ","));
          o += u + "Sub values: " + p + f;
        } else {
          if (((o += u + "Value: "), e.type === s.Type.OID)) {
            var h = s.derToOid(e.value);
            (o += h),
              a.pki &&
                a.pki.oids &&
                h in a.pki.oids &&
                (o += " (" + a.pki.oids[h] + ") ");
          }
          if (e.type === s.Type.INTEGER)
            try {
              o += s.derToInteger(e.value);
            } catch (d) {
              o += "0x" + a.util.bytesToHex(e.value);
            }
          else if (e.type === s.Type.BITSTRING) {
            if (
              (e.value.length > 1
                ? (o += "0x" + a.util.bytesToHex(e.value.slice(1)))
                : (o += "(none)"),
              e.value.length > 0)
            ) {
              var _ = e.value.charCodeAt(0);
              1 == _
                ? (o += " (1 unused bit shown)")
                : _ > 1 && (o += " (" + _ + " unused bits shown)");
            }
          } else if (e.type === s.Type.OCTETSTRING)
            c.test(e.value) || (o += "(" + e.value + ") "),
              (o += "0x" + a.util.bytesToHex(e.value));
          else if (e.type === s.Type.UTF8)
            try {
              o += a.util.decodeUtf8(e.value);
            } catch ($) {
              if ("URI malformed" !== $.message) throw $;
              o += "0x" + a.util.bytesToHex(e.value) + " (malformed UTF8)";
            }
          else
            e.type === s.Type.PRINTABLESTRING || e.type === s.Type.IA5String
              ? (o += e.value)
              : c.test(e.value)
              ? (o += "0x" + a.util.bytesToHex(e.value))
              : 0 === e.value.length
              ? (o += "[null]")
              : (o += e.value);
        }
        return o;
      };
    },
    function (e, r, n) {
      var a = n(0);
      (e.exports = a.md = a.md || {}),
        (a.md.algorithms = a.md.algorithms || {});
    },
    function (e, r, n) {
      var a = n(0);
      function s(e, r) {
        a.cipher.registerAlgorithm(e, function () {
          return new a.aes.Algorithm(e, r);
        });
      }
      n(13),
        n(19),
        n(1),
        (e.exports = a.aes = a.aes || {}),
        (a.aes.startEncrypting = function (e, r, n, a) {
          var s = $({ key: e, output: n, decrypt: !1, mode: a });
          return s.start(r), s;
        }),
        (a.aes.createEncryptionCipher = function (e, r) {
          return $({ key: e, output: null, decrypt: !1, mode: r });
        }),
        (a.aes.startDecrypting = function (e, r, n, a) {
          var s = $({ key: e, output: n, decrypt: !0, mode: a });
          return s.start(r), s;
        }),
        (a.aes.createDecryptionCipher = function (e, r) {
          return $({ key: e, output: null, decrypt: !0, mode: r });
        }),
        (a.aes.Algorithm = function (e, r) {
          f || h();
          var n = this;
          (n.name = e),
            (n.mode = new r({
              blockSize: 16,
              cipher: {
                encrypt: function (e, r) {
                  return _(n._w, e, r, !1);
                },
                decrypt: function (e, r) {
                  return _(n._w, e, r, !0);
                },
              },
            })),
            (n._init = !1);
        }),
        (a.aes.Algorithm.prototype.initialize = function (e) {
          if (!this._init) {
            var r,
              n = e.key;
            if (
              "string" != typeof n ||
              (16 !== n.length && 24 !== n.length && 32 !== n.length)
            ) {
              if (
                a.util.isArray(n) &&
                (16 === n.length || 24 === n.length || 32 === n.length)
              ) {
                (r = n), (n = a.util.createBuffer());
                for (var s = 0; s < r.length; ++s) n.putByte(r[s]);
              }
            } else n = a.util.createBuffer(n);
            if (!a.util.isArray(n)) {
              (r = n), (n = []);
              var o = r.length();
              if (16 === o || 24 === o || 32 === o)
                for (o >>>= 2, s = 0; s < o; ++s) n.push(r.getInt32());
            }
            if (
              !a.util.isArray(n) ||
              (4 !== n.length && 6 !== n.length && 8 !== n.length)
            )
              throw Error("Invalid key parameter.");
            var c = -1 !== ["CFB", "OFB", "CTR", "GCM"].indexOf(this.mode.name);
            (this._w = d(n, e.decrypt && !c)), (this._init = !0);
          }
        }),
        (a.aes._expandKey = function (e, r) {
          return f || h(), d(e, r);
        }),
        (a.aes._updateBlock = _),
        s("AES-ECB", a.cipher.modes.ecb),
        s("AES-CBC", a.cipher.modes.cbc),
        s("AES-CFB", a.cipher.modes.cfb),
        s("AES-OFB", a.cipher.modes.ofb),
        s("AES-CTR", a.cipher.modes.ctr),
        s("AES-GCM", a.cipher.modes.gcm);
      var o,
        c,
        u,
        l,
        p,
        f = !1;
      function h() {
        (f = !0), (u = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54]);
        for (var e = Array(256), r = 0; r < 128; ++r)
          (e[r] = r << 1), (e[r + 128] = ((r + 128) << 1) ^ 283);
        for (
          o = Array(256), c = Array(256), l = [, , , ,], p = [, , , ,], r = 0;
          r < 4;
          ++r
        )
          (l[r] = Array(256)), (p[r] = Array(256));
        var n,
          a,
          s,
          h,
          d,
          _,
          $,
          y = 0,
          g = 0;
        for (r = 0; r < 256; ++r) {
          (h =
            ((h = g ^ (g << 1) ^ (g << 2) ^ (g << 3) ^ (g << 4)) >> 8) ^
            (255 & h) ^
            99),
            (o[y] = h),
            (c[h] = y),
            (_ = ((d = e[h]) << 24) ^ (h << 16) ^ (h << 8) ^ h ^ d),
            ($ =
              (((n = e[y]) ^ (a = e[n]) ^ (s = e[a])) << 24) ^
              ((y ^ s) << 16) ^
              ((y ^ a ^ s) << 8) ^
              y ^
              n ^
              s);
          for (var v = 0; v < 4; ++v)
            (l[v][y] = _),
              (p[v][h] = $),
              (_ = (_ << 24) | (_ >>> 8)),
              ($ = ($ << 24) | ($ >>> 8));
          0 === y ? (y = g = 1) : ((y = n ^ e[e[e[n ^ s]]]), (g ^= e[e[g]]));
        }
      }
      function d(e, r) {
        for (
          var n,
            a = e.slice(0),
            s = 1,
            c = a.length,
            l = 4 * (c + 6 + 1),
            f = c;
          f < l;
          ++f
        )
          (n = a[f - 1]),
            f % c == 0
              ? ((n =
                  (o[(n >>> 16) & 255] << 24) ^
                  (o[(n >>> 8) & 255] << 16) ^
                  (o[255 & n] << 8) ^
                  o[n >>> 24] ^
                  (u[s] << 24)),
                s++)
              : c > 6 &&
                f % c == 4 &&
                (n =
                  (o[n >>> 24] << 24) ^
                  (o[(n >>> 16) & 255] << 16) ^
                  (o[(n >>> 8) & 255] << 8) ^
                  o[255 & n]),
            (a[f] = a[f - c] ^ n);
        if (r) {
          for (
            var h,
              d = p[0],
              _ = p[1],
              $ = p[2],
              y = p[3],
              g = a.slice(0),
              v = ((f = 0), (l = a.length) - 4);
            f < l;
            f += 4, v -= 4
          )
            if (0 === f || f === l - 4)
              (g[f] = a[v]),
                (g[f + 1] = a[v + 3]),
                (g[f + 2] = a[v + 2]),
                (g[f + 3] = a[v + 1]);
            else
              for (var m = 0; m < 4; ++m)
                (h = a[v + m]),
                  (g[f + (3 & -m)] =
                    d[o[h >>> 24]] ^
                    _[o[(h >>> 16) & 255]] ^
                    $[o[(h >>> 8) & 255]] ^
                    y[o[255 & h]]);
          a = g;
        }
        return a;
      }
      function _(e, r, n, a) {
        var s,
          u,
          f,
          h,
          d,
          _,
          $,
          y,
          g,
          v,
          m,
          C,
          E = e.length / 4 - 1;
        a
          ? ((s = p[0]), (u = p[1]), (f = p[2]), (h = p[3]), (d = c))
          : ((s = l[0]), (u = l[1]), (f = l[2]), (h = l[3]), (d = o)),
          (_ = r[0] ^ e[0]),
          ($ = r[a ? 3 : 1] ^ e[1]),
          (y = r[2] ^ e[2]),
          (g = r[a ? 1 : 3] ^ e[3]);
        for (var S = 3, T = 1; T < E; ++T)
          (v =
            s[_ >>> 24] ^
            u[($ >>> 16) & 255] ^
            f[(y >>> 8) & 255] ^
            h[255 & g] ^
            e[++S]),
            (m =
              s[$ >>> 24] ^
              u[(y >>> 16) & 255] ^
              f[(g >>> 8) & 255] ^
              h[255 & _] ^
              e[++S]),
            (C =
              s[y >>> 24] ^
              u[(g >>> 16) & 255] ^
              f[(_ >>> 8) & 255] ^
              h[255 & $] ^
              e[++S]),
            (g =
              s[g >>> 24] ^
              u[(_ >>> 16) & 255] ^
              f[($ >>> 8) & 255] ^
              h[255 & y] ^
              e[++S]),
            (_ = v),
            ($ = m),
            (y = C);
        (n[0] =
          (d[_ >>> 24] << 24) ^
          (d[($ >>> 16) & 255] << 16) ^
          (d[(y >>> 8) & 255] << 8) ^
          d[255 & g] ^
          e[++S]),
          (n[a ? 3 : 1] =
            (d[$ >>> 24] << 24) ^
            (d[(y >>> 16) & 255] << 16) ^
            (d[(g >>> 8) & 255] << 8) ^
            d[255 & _] ^
            e[++S]),
          (n[2] =
            (d[y >>> 24] << 24) ^
            (d[(g >>> 16) & 255] << 16) ^
            (d[(_ >>> 8) & 255] << 8) ^
            d[255 & $] ^
            e[++S]),
          (n[a ? 1 : 3] =
            (d[g >>> 24] << 24) ^
            (d[(_ >>> 16) & 255] << 16) ^
            (d[($ >>> 8) & 255] << 8) ^
            d[255 & y] ^
            e[++S]);
      }
      function $(e) {
        var r,
          n = "AES-" + ((e = e || {}).mode || "CBC").toUpperCase(),
          s = (r = e.decrypt
            ? a.cipher.createDecipher(n, e.key)
            : a.cipher.createCipher(n, e.key)).start;
        return (
          (r.start = function (e, n) {
            var o = null;
            n instanceof a.util.ByteBuffer && ((o = n), (n = {})),
              ((n = n || {}).output = o),
              (n.iv = e),
              s.call(r, n);
          }),
          r
        );
      }
    },
    function (e, r, n) {
      var a = n(0);
      a.pki = a.pki || {};
      var s = (e.exports = a.pki.oids = a.oids = a.oids || {});
      function o(e, r) {
        (s[e] = r), (s[r] = e);
      }
      function c(e, r) {
        s[e] = r;
      }
      o("1.2.840.113549.1.1.1", "rsaEncryption"),
        o("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
        o("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
        o("1.2.840.113549.1.1.7", "RSAES-OAEP"),
        o("1.2.840.113549.1.1.8", "mgf1"),
        o("1.2.840.113549.1.1.9", "pSpecified"),
        o("1.2.840.113549.1.1.10", "RSASSA-PSS"),
        o("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
        o("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
        o("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
        o("1.3.101.112", "EdDSA25519"),
        o("1.2.840.10040.4.3", "dsa-with-sha1"),
        o("1.3.14.3.2.7", "desCBC"),
        o("1.3.14.3.2.26", "sha1"),
        o("1.3.14.3.2.29", "sha1WithRSASignature"),
        o("2.16.840.1.101.3.4.2.1", "sha256"),
        o("2.16.840.1.101.3.4.2.2", "sha384"),
        o("2.16.840.1.101.3.4.2.3", "sha512"),
        o("2.16.840.1.101.3.4.2.4", "sha224"),
        o("2.16.840.1.101.3.4.2.5", "sha512-224"),
        o("2.16.840.1.101.3.4.2.6", "sha512-256"),
        o("1.2.840.113549.2.2", "md2"),
        o("1.2.840.113549.2.5", "md5"),
        o("1.2.840.113549.1.7.1", "data"),
        o("1.2.840.113549.1.7.2", "signedData"),
        o("1.2.840.113549.1.7.3", "envelopedData"),
        o("1.2.840.113549.1.7.4", "signedAndEnvelopedData"),
        o("1.2.840.113549.1.7.5", "digestedData"),
        o("1.2.840.113549.1.7.6", "encryptedData"),
        o("1.2.840.113549.1.9.1", "emailAddress"),
        o("1.2.840.113549.1.9.2", "unstructuredName"),
        o("1.2.840.113549.1.9.3", "contentType"),
        o("1.2.840.113549.1.9.4", "messageDigest"),
        o("1.2.840.113549.1.9.5", "signingTime"),
        o("1.2.840.113549.1.9.6", "counterSignature"),
        o("1.2.840.113549.1.9.7", "challengePassword"),
        o("1.2.840.113549.1.9.8", "unstructuredAddress"),
        o("1.2.840.113549.1.9.14", "extensionRequest"),
        o("1.2.840.113549.1.9.20", "friendlyName"),
        o("1.2.840.113549.1.9.21", "localKeyId"),
        o("1.2.840.113549.1.9.22.1", "x509Certificate"),
        o("1.2.840.113549.1.12.10.1.1", "keyBag"),
        o("1.2.840.113549.1.12.10.1.2", "pkcs8ShroudedKeyBag"),
        o("1.2.840.113549.1.12.10.1.3", "certBag"),
        o("1.2.840.113549.1.12.10.1.4", "crlBag"),
        o("1.2.840.113549.1.12.10.1.5", "secretBag"),
        o("1.2.840.113549.1.12.10.1.6", "safeContentsBag"),
        o("1.2.840.113549.1.5.13", "pkcs5PBES2"),
        o("1.2.840.113549.1.5.12", "pkcs5PBKDF2"),
        o("1.2.840.113549.1.12.1.1", "pbeWithSHAAnd128BitRC4"),
        o("1.2.840.113549.1.12.1.2", "pbeWithSHAAnd40BitRC4"),
        o("1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC"),
        o("1.2.840.113549.1.12.1.4", "pbeWithSHAAnd2-KeyTripleDES-CBC"),
        o("1.2.840.113549.1.12.1.5", "pbeWithSHAAnd128BitRC2-CBC"),
        o("1.2.840.113549.1.12.1.6", "pbewithSHAAnd40BitRC2-CBC"),
        o("1.2.840.113549.2.7", "hmacWithSHA1"),
        o("1.2.840.113549.2.8", "hmacWithSHA224"),
        o("1.2.840.113549.2.9", "hmacWithSHA256"),
        o("1.2.840.113549.2.10", "hmacWithSHA384"),
        o("1.2.840.113549.2.11", "hmacWithSHA512"),
        o("1.2.840.113549.3.7", "des-EDE3-CBC"),
        o("2.16.840.1.101.3.4.1.2", "aes128-CBC"),
        o("2.16.840.1.101.3.4.1.22", "aes192-CBC"),
        o("2.16.840.1.101.3.4.1.42", "aes256-CBC"),
        o("2.5.4.3", "commonName"),
        o("2.5.4.4", "surname"),
        o("2.5.4.5", "serialNumber"),
        o("2.5.4.6", "countryName"),
        o("2.5.4.7", "localityName"),
        o("2.5.4.8", "stateOrProvinceName"),
        o("2.5.4.9", "streetAddress"),
        o("2.5.4.10", "organizationName"),
        o("2.5.4.11", "organizationalUnitName"),
        o("2.5.4.12", "title"),
        o("2.5.4.13", "description"),
        o("2.5.4.15", "businessCategory"),
        o("2.5.4.17", "postalCode"),
        o("2.5.4.42", "givenName"),
        o(
          "1.3.6.1.4.1.311.60.2.1.2",
          "jurisdictionOfIncorporationStateOrProvinceName"
        ),
        o("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionOfIncorporationCountryName"),
        o("2.16.840.1.113730.1.1", "nsCertType"),
        o("2.16.840.1.113730.1.13", "nsComment"),
        (s["2.5.29.1"] = "authorityKeyIdentifier"),
        (s["2.5.29.2"] = "keyAttributes"),
        (s["2.5.29.3"] = "certificatePolicies"),
        (s["2.5.29.4"] = "keyUsageRestriction"),
        (s["2.5.29.5"] = "policyMapping"),
        (s["2.5.29.6"] = "subtreesConstraint"),
        (s["2.5.29.7"] = "subjectAltName"),
        (s["2.5.29.8"] = "issuerAltName"),
        (s["2.5.29.9"] = "subjectDirectoryAttributes"),
        (s["2.5.29.10"] = "basicConstraints"),
        (s["2.5.29.11"] = "nameConstraints"),
        (s["2.5.29.12"] = "policyConstraints"),
        (s["2.5.29.13"] = "basicConstraints"),
        o("2.5.29.14", "subjectKeyIdentifier"),
        o("2.5.29.15", "keyUsage"),
        (s["2.5.29.16"] = "privateKeyUsagePeriod"),
        o("2.5.29.17", "subjectAltName"),
        o("2.5.29.18", "issuerAltName"),
        o("2.5.29.19", "basicConstraints"),
        (s["2.5.29.20"] = "cRLNumber"),
        (s["2.5.29.21"] = "cRLReason"),
        (s["2.5.29.22"] = "expirationDate"),
        (s["2.5.29.23"] = "instructionCode"),
        (s["2.5.29.24"] = "invalidityDate"),
        (s["2.5.29.25"] = "cRLDistributionPoints"),
        (s["2.5.29.26"] = "issuingDistributionPoint"),
        (s["2.5.29.27"] = "deltaCRLIndicator"),
        (s["2.5.29.28"] = "issuingDistributionPoint"),
        (s["2.5.29.29"] = "certificateIssuer"),
        (s["2.5.29.30"] = "nameConstraints"),
        o("2.5.29.31", "cRLDistributionPoints"),
        o("2.5.29.32", "certificatePolicies"),
        (s["2.5.29.33"] = "policyMappings"),
        (s["2.5.29.34"] = "policyConstraints"),
        o("2.5.29.35", "authorityKeyIdentifier"),
        (s["2.5.29.36"] = "policyConstraints"),
        o("2.5.29.37", "extKeyUsage"),
        (s["2.5.29.46"] = "freshestCRL"),
        (s["2.5.29.54"] = "inhibitAnyPolicy"),
        o("1.3.6.1.4.1.11129.2.4.2", "timestampList"),
        o("1.3.6.1.5.5.7.1.1", "authorityInfoAccess"),
        o("1.3.6.1.5.5.7.3.1", "serverAuth"),
        o("1.3.6.1.5.5.7.3.2", "clientAuth"),
        o("1.3.6.1.5.5.7.3.3", "codeSigning"),
        o("1.3.6.1.5.5.7.3.4", "emailProtection"),
        o("1.3.6.1.5.5.7.3.8", "timeStamping");
    },
    function (e, r, n) {
      var a = n(0);
      n(1);
      var s = (e.exports = a.pem = a.pem || {});
      function o(e) {
        for (
          var r = e.name + ": ",
            n = [],
            a = function (e, r) {
              return " " + r;
            },
            s = 0;
          s < e.values.length;
          ++s
        )
          n.push(e.values[s].replace(/^(\S+\r\n)/, a));
        r += n.join(",") + "\r\n";
        var o = 0,
          c = -1;
        for (s = 0; s < r.length; ++s, ++o)
          if (o > 65 && -1 !== c) {
            var u = r[c];
            "," === u
              ? (++c, (r = r.substr(0, c) + "\r\n " + r.substr(c)))
              : (r = r.substr(0, c) + "\r\n" + u + r.substr(c + 1)),
              (o = s - c - 1),
              (c = -1),
              ++s;
          } else (" " !== r[s] && "	" !== r[s] && "," !== r[s]) || (c = s);
        return r;
      }
      function c(e) {
        return e.replace(/^\s+/, "");
      }
      (s.encode = function (e, r) {
        r = r || {};
        var n,
          s = "-----BEGIN " + e.type + "-----\r\n";
        if (
          (e.procType &&
            (s += o(
              (n = {
                name: "Proc-Type",
                values: [String(e.procType.version), e.procType.type],
              })
            )),
          e.contentDomain &&
            (s += o(
              (n = { name: "Content-Domain", values: [e.contentDomain] })
            )),
          e.dekInfo &&
            ((n = { name: "DEK-Info", values: [e.dekInfo.algorithm] }),
            e.dekInfo.parameters && n.values.push(e.dekInfo.parameters),
            (s += o(n))),
          e.headers)
        )
          for (var c = 0; c < e.headers.length; ++c) s += o(e.headers[c]);
        return (
          e.procType && (s += "\r\n"),
          (s += a.util.encode64(e.body, r.maxline || 64) + "\r\n"),
          (s += "-----END " + e.type + "-----\r\n")
        );
      }),
        (s.decode = function (e) {
          for (
            var r,
              n = [],
              s =
                /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+\/=\s]+?)-----END \1-----/g,
              o = /([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+)/,
              u = /\r?\n/;
            (r = s.exec(e));

          ) {
            var l = r[1];
            "NEW CERTIFICATE REQUEST" === l && (l = "CERTIFICATE REQUEST");
            var p = {
              type: l,
              procType: null,
              contentDomain: null,
              dekInfo: null,
              headers: [],
              body: a.util.decode64(r[3]),
            };
            if ((n.push(p), r[2])) {
              for (var f = r[2].split(u), h = 0; r && h < f.length; ) {
                for (
                  var d = f[h].replace(/\s+$/, ""), _ = h + 1;
                  _ < f.length;
                  ++_
                ) {
                  var $ = f[_];
                  if (!/\s/.test($[0])) break;
                  (d += $), (h = _);
                }
                if ((r = d.match(o))) {
                  for (
                    var y = { name: r[1], values: [] },
                      g = r[2].split(","),
                      v = 0;
                    v < g.length;
                    ++v
                  )
                    y.values.push(c(g[v]));
                  if (p.procType) {
                    if (p.contentDomain || "Content-Domain" !== y.name) {
                      if (p.dekInfo || "DEK-Info" !== y.name) p.headers.push(y);
                      else {
                        if (0 === y.values.length)
                          throw Error(
                            'Invalid PEM formatted message. The "DEK-Info" header must have at least one subfield.'
                          );
                        p.dekInfo = {
                          algorithm: g[0],
                          parameters: g[1] || null,
                        };
                      }
                    } else p.contentDomain = g[0] || "";
                  } else {
                    if ("Proc-Type" !== y.name)
                      throw Error(
                        'Invalid PEM formatted message. The first encapsulated header must be "Proc-Type".'
                      );
                    if (2 !== y.values.length)
                      throw Error(
                        'Invalid PEM formatted message. The "Proc-Type" header must have two subfields.'
                      );
                    p.procType = { version: g[0], type: g[1] };
                  }
                }
                ++h;
              }
              if ("ENCRYPTED" === p.procType && !p.dekInfo)
                throw Error(
                  'Invalid PEM formatted message. The "DEK-Info" header must be present if "Proc-Type" is "ENCRYPTED".'
                );
            }
          }
          if (0 === n.length) throw Error("Invalid PEM formatted message.");
          return n;
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(4),
        n(1),
        ((e.exports = a.hmac = a.hmac || {}).create = function () {
          var e = null,
            r = null,
            n = null,
            s = null,
            o = {
              start: function (o, c) {
                if (null !== o) {
                  if ("string" == typeof o) {
                    if (!((o = o.toLowerCase()) in a.md.algorithms))
                      throw Error('Unknown hash algorithm "' + o + '"');
                    r = a.md.algorithms[o].create();
                  } else r = o;
                }
                if (null === c) c = e;
                else {
                  if ("string" == typeof c) c = a.util.createBuffer(c);
                  else if (a.util.isArray(c)) {
                    var u = c;
                    c = a.util.createBuffer();
                    for (var l = 0; l < u.length; ++l) c.putByte(u[l]);
                  }
                  var p = c.length();
                  for (
                    p > r.blockLength &&
                      (r.start(), r.update(c.bytes()), (c = r.digest())),
                      n = a.util.createBuffer(),
                      s = a.util.createBuffer(),
                      p = c.length(),
                      l = 0;
                    l < p;
                    ++l
                  )
                    (u = c.at(l)), n.putByte(54 ^ u), s.putByte(92 ^ u);
                  if (p < r.blockLength)
                    for (u = r.blockLength - p, l = 0; l < u; ++l)
                      n.putByte(54), s.putByte(92);
                  (e = c), (n = n.bytes()), (s = s.bytes());
                }
                r.start(), r.update(n);
              },
              update: function (e) {
                r.update(e);
              },
              getMac: function () {
                var e = r.digest().bytes();
                return r.start(), r.update(s), r.update(e), r.digest();
              },
            };
          return (o.digest = o.getMac), o;
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(4), n(1);
      var s = (e.exports = a.sha1 = a.sha1 || {});
      (a.md.sha1 = a.md.algorithms.sha1 = s),
        (s.create = function () {
          c || ((o = "\x80"), (o += a.util.fillString("\0", 64)), (c = !0));
          var e = null,
            r = a.util.createBuffer(),
            n = Array(80),
            s = {
              algorithm: "sha1",
              blockLength: 64,
              digestLength: 20,
              messageLength: 0,
              fullMessageLength: null,
              messageLengthSize: 8,
              start: function () {
                (s.messageLength = 0),
                  (s.fullMessageLength = s.messageLength64 = []);
                for (var n = s.messageLengthSize / 4, o = 0; o < n; ++o)
                  s.fullMessageLength.push(0);
                return (
                  (r = a.util.createBuffer()),
                  (e = {
                    h0: 1732584193,
                    h1: 4023233417,
                    h2: 2562383102,
                    h3: 271733878,
                    h4: 3285377520,
                  }),
                  s
                );
              },
            };
          return (
            s.start(),
            (s.update = function (o, c) {
              "utf8" === c && (o = a.util.encodeUtf8(o));
              var l = o.length;
              (s.messageLength += l), (l = [(l / 4294967296) >>> 0, l >>> 0]);
              for (var p = s.fullMessageLength.length - 1; p >= 0; --p)
                (s.fullMessageLength[p] += l[1]),
                  (l[1] = l[0] + ((s.fullMessageLength[p] / 4294967296) >>> 0)),
                  (s.fullMessageLength[p] = s.fullMessageLength[p] >>> 0),
                  (l[0] = (l[1] / 4294967296) >>> 0);
              return (
                r.putBytes(o),
                u(e, n, r),
                (r.read > 2048 || 0 === r.length()) && r.compact(),
                s
              );
            }),
            (s.digest = function () {
              var c = a.util.createBuffer();
              c.putBytes(r.bytes());
              var l,
                p =
                  (s.fullMessageLength[s.fullMessageLength.length - 1] +
                    s.messageLengthSize) &
                  (s.blockLength - 1);
              c.putBytes(o.substr(0, s.blockLength - p));
              for (
                var f = 8 * s.fullMessageLength[0], h = 0;
                h < s.fullMessageLength.length - 1;
                ++h
              )
                (f +=
                  ((l = 8 * s.fullMessageLength[h + 1]) / 4294967296) >>> 0),
                  c.putInt32(f >>> 0),
                  (f = l >>> 0);
              c.putInt32(f);
              var d = { h0: e.h0, h1: e.h1, h2: e.h2, h3: e.h3, h4: e.h4 };
              u(d, n, c);
              var _ = a.util.createBuffer();
              return (
                _.putInt32(d.h0),
                _.putInt32(d.h1),
                _.putInt32(d.h2),
                _.putInt32(d.h3),
                _.putInt32(d.h4),
                _
              );
            }),
            s
          );
        });
      var o = null,
        c = !1;
      function u(e, r, n) {
        for (var a, s, o, c, u, l, p, f = n.length(); f >= 64; ) {
          for (
            s = e.h0, o = e.h1, c = e.h2, u = e.h3, l = e.h4, p = 0;
            p < 16;
            ++p
          )
            (a = n.getInt32()),
              (r[p] = a),
              (a =
                ((s << 5) | (s >>> 27)) +
                (u ^ (o & (c ^ u))) +
                l +
                1518500249 +
                a),
              (l = u),
              (u = c),
              (c = ((o << 30) | (o >>> 2)) >>> 0),
              (o = s),
              (s = a);
          for (; p < 20; ++p)
            (a =
              ((a = r[p - 3] ^ r[p - 8] ^ r[p - 14] ^ r[p - 16]) << 1) |
              (a >>> 31)),
              (r[p] = a),
              (a =
                ((s << 5) | (s >>> 27)) +
                (u ^ (o & (c ^ u))) +
                l +
                1518500249 +
                a),
              (l = u),
              (u = c),
              (c = ((o << 30) | (o >>> 2)) >>> 0),
              (o = s),
              (s = a);
          for (; p < 32; ++p)
            (a =
              ((a = r[p - 3] ^ r[p - 8] ^ r[p - 14] ^ r[p - 16]) << 1) |
              (a >>> 31)),
              (r[p] = a),
              (a = ((s << 5) | (s >>> 27)) + (o ^ c ^ u) + l + 1859775393 + a),
              (l = u),
              (u = c),
              (c = ((o << 30) | (o >>> 2)) >>> 0),
              (o = s),
              (s = a);
          for (; p < 40; ++p)
            (a =
              ((a = r[p - 6] ^ r[p - 16] ^ r[p - 28] ^ r[p - 32]) << 2) |
              (a >>> 30)),
              (r[p] = a),
              (a = ((s << 5) | (s >>> 27)) + (o ^ c ^ u) + l + 1859775393 + a),
              (l = u),
              (u = c),
              (c = ((o << 30) | (o >>> 2)) >>> 0),
              (o = s),
              (s = a);
          for (; p < 60; ++p)
            (a =
              ((a = r[p - 6] ^ r[p - 16] ^ r[p - 28] ^ r[p - 32]) << 2) |
              (a >>> 30)),
              (r[p] = a),
              (a =
                ((s << 5) | (s >>> 27)) +
                ((o & c) | (u & (o ^ c))) +
                l +
                2400959708 +
                a),
              (l = u),
              (u = c),
              (c = ((o << 30) | (o >>> 2)) >>> 0),
              (o = s),
              (s = a);
          for (; p < 80; ++p)
            (a =
              ((a = r[p - 6] ^ r[p - 16] ^ r[p - 28] ^ r[p - 32]) << 2) |
              (a >>> 30)),
              (r[p] = a),
              (a = ((s << 5) | (s >>> 27)) + (o ^ c ^ u) + l + 3395469782 + a),
              (l = u),
              (u = c),
              (c = ((o << 30) | (o >>> 2)) >>> 0),
              (o = s),
              (s = a);
          (e.h0 = (e.h0 + s) | 0),
            (e.h1 = (e.h1 + o) | 0),
            (e.h2 = (e.h2 + c) | 0),
            (e.h3 = (e.h3 + u) | 0),
            (e.h4 = (e.h4 + l) | 0),
            (f -= 64);
        }
      }
    },
    function (e, r, n) {
      var a = n(0);
      function s(e, r) {
        a.cipher.registerAlgorithm(e, function () {
          return new a.des.Algorithm(e, r);
        });
      }
      n(13),
        n(19),
        n(1),
        (e.exports = a.des = a.des || {}),
        (a.des.startEncrypting = function (e, r, n, a) {
          var s = $({
            key: e,
            output: n,
            decrypt: !1,
            mode: a || (null === r ? "ECB" : "CBC"),
          });
          return s.start(r), s;
        }),
        (a.des.createEncryptionCipher = function (e, r) {
          return $({ key: e, output: null, decrypt: !1, mode: r });
        }),
        (a.des.startDecrypting = function (e, r, n, a) {
          var s = $({
            key: e,
            output: n,
            decrypt: !0,
            mode: a || (null === r ? "ECB" : "CBC"),
          });
          return s.start(r), s;
        }),
        (a.des.createDecryptionCipher = function (e, r) {
          return $({ key: e, output: null, decrypt: !0, mode: r });
        }),
        (a.des.Algorithm = function (e, r) {
          var n = this;
          (n.name = e),
            (n.mode = new r({
              blockSize: 8,
              cipher: {
                encrypt: function (e, r) {
                  return _(n._keys, e, r, !1);
                },
                decrypt: function (e, r) {
                  return _(n._keys, e, r, !0);
                },
              },
            })),
            (n._init = !1);
        }),
        (a.des.Algorithm.prototype.initialize = function (e) {
          if (!this._init) {
            var r = a.util.createBuffer(e.key);
            if (0 === this.name.indexOf("3DES") && 24 !== r.length())
              throw Error("Invalid Triple-DES key size: " + 8 * r.length());
            (this._keys = (function (e) {
              for (
                var r,
                  n = [
                    0, 4, 536870912, 536870916, 65536, 65540, 536936448,
                    536936452, 512, 516, 536871424, 536871428, 66048, 66052,
                    536936960, 536936964,
                  ],
                  a = [
                    0, 1, 1048576, 1048577, 67108864, 67108865, 68157440,
                    68157441, 256, 257, 1048832, 1048833, 67109120, 67109121,
                    68157696, 68157697,
                  ],
                  s = [
                    0, 8, 2048, 2056, 16777216, 16777224, 16779264, 16779272, 0,
                    8, 2048, 2056, 16777216, 16777224, 16779264, 16779272,
                  ],
                  o = [
                    0, 2097152, 134217728, 136314880, 8192, 2105344, 134225920,
                    136323072, 131072, 2228224, 134348800, 136445952, 139264,
                    2236416, 134356992, 136454144,
                  ],
                  c = [
                    0, 262144, 16, 262160, 0, 262144, 16, 262160, 4096, 266240,
                    4112, 266256, 4096, 266240, 4112, 266256,
                  ],
                  u = [
                    0, 1024, 32, 1056, 0, 1024, 32, 1056, 33554432, 33555456,
                    33554464, 33555488, 33554432, 33555456, 33554464, 33555488,
                  ],
                  l = [
                    0, 268435456, 524288, 268959744, 2, 268435458, 524290,
                    268959746, 0, 268435456, 524288, 268959744, 2, 268435458,
                    524290, 268959746,
                  ],
                  p = [
                    0, 65536, 2048, 67584, 536870912, 536936448, 536872960,
                    536938496, 131072, 196608, 133120, 198656, 537001984,
                    537067520, 537004032, 537069568,
                  ],
                  f = [
                    0, 262144, 0, 262144, 2, 262146, 2, 262146, 33554432,
                    33816576, 33554432, 33816576, 33554434, 33816578, 33554434,
                    33816578,
                  ],
                  h = [
                    0, 268435456, 8, 268435464, 0, 268435456, 8, 268435464,
                    1024, 268436480, 1032, 268436488, 1024, 268436480, 1032,
                    268436488,
                  ],
                  d = [
                    0, 32, 0, 32, 1048576, 1048608, 1048576, 1048608, 8192,
                    8224, 8192, 8224, 1056768, 1056800, 1056768, 1056800,
                  ],
                  _ = [
                    0, 16777216, 512, 16777728, 2097152, 18874368, 2097664,
                    18874880, 67108864, 83886080, 67109376, 83886592, 69206016,
                    85983232, 69206528, 85983744,
                  ],
                  $ = [
                    0, 4096, 134217728, 134221824, 524288, 528384, 134742016,
                    134746112, 16, 4112, 134217744, 134221840, 524304, 528400,
                    134742032, 134746128,
                  ],
                  y = [
                    0, 4, 256, 260, 0, 4, 256, 260, 1, 5, 257, 261, 1, 5, 257,
                    261,
                  ],
                  g = e.length() > 8 ? 3 : 1,
                  v = [],
                  m = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0],
                  C = 0,
                  E = 0;
                E < g;
                E++
              ) {
                var S = e.getInt32(),
                  T = e.getInt32();
                (S ^= (r = 252645135 & ((S >>> 4) ^ T)) << 4),
                  (S ^= r = 65535 & (((T ^= r) >>> -16) ^ S)),
                  (S ^= (r = 858993459 & ((S >>> 2) ^ (T ^= r << -16))) << 2),
                  (S ^= r = 65535 & (((T ^= r) >>> -16) ^ S)),
                  (S ^= (r = 1431655765 & ((S >>> 1) ^ (T ^= r << -16))) << 1),
                  (S ^= r = 16711935 & (((T ^= r) >>> 8) ^ S)),
                  (r =
                    ((S ^=
                      (r = 1431655765 & ((S >>> 1) ^ (T ^= r << 8))) << 1) <<
                      8) |
                    (((T ^= r) >>> 20) & 240)),
                  (S =
                    (T << 24) |
                    ((T << 8) & 16711680) |
                    ((T >>> 8) & 65280) |
                    ((T >>> 24) & 240)),
                  (T = r);
                for (var B = 0; B < m.length; ++B) {
                  m[B]
                    ? ((S = (S << 2) | (S >>> 26)), (T = (T << 2) | (T >>> 26)))
                    : ((S = (S << 1) | (S >>> 27)),
                      (T = (T << 1) | (T >>> 27)));
                  var I =
                      n[(S &= -15) >>> 28] |
                      a[(S >>> 24) & 15] |
                      s[(S >>> 20) & 15] |
                      o[(S >>> 16) & 15] |
                      c[(S >>> 12) & 15] |
                      u[(S >>> 8) & 15] |
                      l[(S >>> 4) & 15],
                    A =
                      p[(T &= -15) >>> 28] |
                      f[(T >>> 24) & 15] |
                      h[(T >>> 20) & 15] |
                      d[(T >>> 16) & 15] |
                      _[(T >>> 12) & 15] |
                      $[(T >>> 8) & 15] |
                      y[(T >>> 4) & 15];
                  (r = 65535 & ((A >>> 16) ^ I)),
                    (v[C++] = I ^ r),
                    (v[C++] = A ^ (r << 16));
                }
              }
              return v;
            })(r)),
              (this._init = !0);
          }
        }),
        s("DES-ECB", a.cipher.modes.ecb),
        s("DES-CBC", a.cipher.modes.cbc),
        s("DES-CFB", a.cipher.modes.cfb),
        s("DES-OFB", a.cipher.modes.ofb),
        s("DES-CTR", a.cipher.modes.ctr),
        s("3DES-ECB", a.cipher.modes.ecb),
        s("3DES-CBC", a.cipher.modes.cbc),
        s("3DES-CFB", a.cipher.modes.cfb),
        s("3DES-OFB", a.cipher.modes.ofb),
        s("3DES-CTR", a.cipher.modes.ctr);
      var o = [
          16843776, 0, 65536, 16843780, 16842756, 66564, 4, 65536, 1024,
          16843776, 16843780, 1024, 16778244, 16842756, 16777216, 4, 1028,
          16778240, 16778240, 66560, 66560, 16842752, 16842752, 16778244, 65540,
          16777220, 16777220, 65540, 0, 1028, 66564, 16777216, 65536, 16843780,
          4, 16842752, 16843776, 16777216, 16777216, 1024, 16842756, 65536,
          66560, 16777220, 1024, 4, 16778244, 66564, 16843780, 65540, 16842752,
          16778244, 16777220, 1028, 66564, 16843776, 1028, 16778240, 16778240,
          0, 65540, 66560, 0, 16842756,
        ],
        c = [
          -2146402272, -2147450880, 32768, 1081376, 1048576, 32, -2146435040,
          -2147450848, -2147483616, -2146402272, -2146402304, -2147483648,
          -2147450880, 1048576, 32, -2146435040, 1081344, 1048608, -2147450848,
          0, -2147483648, 32768, 1081376, -2146435072, 1048608, -2147483616, 0,
          1081344, 32800, -2146402304, -2146435072, 32800, 0, 1081376,
          -2146435040, 1048576, -2147450848, -2146435072, -2146402304, 32768,
          -2146435072, -2147450880, 32, -2146402272, 1081376, 32, 32768,
          -2147483648, 32800, -2146402304, 1048576, -2147483616, 1048608,
          -2147450848, -2147483616, 1048608, 1081344, 0, -2147450880, 32800,
          -2147483648, -2146435040, -2146402272, 1081344,
        ],
        u = [
          520, 134349312, 0, 134348808, 134218240, 0, 131592, 134218240, 131080,
          134217736, 134217736, 131072, 134349320, 131080, 134348800, 520,
          134217728, 8, 134349312, 512, 131584, 134348800, 134348808, 131592,
          134218248, 131584, 131072, 134218248, 8, 134349320, 512, 134217728,
          134349312, 134217728, 131080, 520, 131072, 134349312, 134218240, 0,
          512, 131080, 134349320, 134218240, 134217736, 512, 0, 134348808,
          134218248, 131072, 134217728, 134349320, 8, 131592, 131584, 134217736,
          134348800, 134218248, 520, 134348800, 131592, 8, 134348808, 131584,
        ],
        l = [
          8396801, 8321, 8321, 128, 8396928, 8388737, 8388609, 8193, 0, 8396800,
          8396800, 8396929, 129, 0, 8388736, 8388609, 1, 8192, 8388608, 8396801,
          128, 8388608, 8193, 8320, 8388737, 1, 8320, 8388736, 8192, 8396928,
          8396929, 129, 8388736, 8388609, 8396800, 8396929, 129, 0, 0, 8396800,
          8320, 8388736, 8388737, 1, 8396801, 8321, 8321, 128, 8396929, 129, 1,
          8192, 8388609, 8193, 8396928, 8388737, 8193, 8320, 8388608, 8396801,
          128, 8388608, 8192, 8396928,
        ],
        p = [
          256, 34078976, 34078720, 1107296512, 524288, 256, 1073741824,
          34078720, 1074266368, 524288, 33554688, 1074266368, 1107296512,
          1107820544, 524544, 1073741824, 33554432, 1074266112, 1074266112, 0,
          1073742080, 1107820800, 1107820800, 33554688, 1107820544, 1073742080,
          0, 1107296256, 34078976, 33554432, 1107296256, 524544, 524288,
          1107296512, 256, 33554432, 1073741824, 34078720, 1107296512,
          1074266368, 33554688, 1073741824, 1107820544, 34078976, 1074266368,
          256, 33554432, 1107820544, 1107820800, 524544, 1107296256, 1107820800,
          34078720, 0, 1074266112, 1107296256, 524544, 33554688, 1073742080,
          524288, 0, 1074266112, 34078976, 1073742080,
        ],
        f = [
          536870928, 541065216, 16384, 541081616, 541065216, 16, 541081616,
          4194304, 536887296, 4210704, 4194304, 536870928, 4194320, 536887296,
          536870912, 16400, 0, 4194320, 536887312, 16384, 4210688, 536887312,
          16, 541065232, 541065232, 0, 4210704, 541081600, 16400, 4210688,
          541081600, 536870912, 536887296, 16, 541065232, 4210688, 541081616,
          4194304, 16400, 536870928, 4194304, 536887296, 536870912, 16400,
          536870928, 541081616, 4210688, 541065216, 4210704, 541081600, 0,
          541065232, 16, 16384, 541065216, 4210704, 16384, 4194320, 536887312,
          0, 541081600, 536870912, 4194320, 536887312,
        ],
        h = [
          2097152, 69206018, 67110914, 0, 2048, 67110914, 2099202, 69208064,
          69208066, 2097152, 0, 67108866, 2, 67108864, 69206018, 2050, 67110912,
          2099202, 2097154, 67110912, 67108866, 69206016, 69208064, 2097154,
          69206016, 2048, 2050, 69208066, 2099200, 2, 67108864, 2099200,
          67108864, 2099200, 2097152, 67110914, 67110914, 69206018, 69206018, 2,
          2097154, 67108864, 67110912, 2097152, 69208064, 2050, 2099202,
          69208064, 2050, 67108866, 69208066, 69206016, 2099200, 0, 2, 69208066,
          0, 2099202, 69206016, 2048, 67108866, 67110912, 2048, 2097154,
        ],
        d = [
          268439616, 4096, 262144, 268701760, 268435456, 268439616, 64,
          268435456, 262208, 268697600, 268701760, 266240, 268701696, 266304,
          4096, 64, 268697600, 268435520, 268439552, 4160, 266240, 262208,
          268697664, 268701696, 4160, 0, 0, 268697664, 268435520, 268439552,
          266304, 262144, 266304, 262144, 268701696, 4096, 64, 268697664, 4096,
          266304, 268439552, 64, 268435520, 268697600, 268697664, 268435456,
          262144, 268439616, 0, 268701760, 262208, 268435520, 268697600,
          268439552, 268439616, 0, 268701760, 266240, 266240, 4160, 4160,
          262208, 268435456, 268701696,
        ];
      function _(e, r, n, a) {
        var s,
          _,
          $ = 32 === e.length ? 3 : 9;
        s =
          3 === $
            ? a
              ? [30, -2, -2]
              : [0, 32, 2]
            : a
            ? [94, 62, -2, 32, 64, 2, 30, -2, -2]
            : [0, 32, 2, 62, 30, -2, 64, 96, 2];
        var y = r[0],
          g = r[1];
        (y ^= (_ = 252645135 & ((y >>> 4) ^ g)) << 4),
          (y ^= (_ = 65535 & ((y >>> 16) ^ (g ^= _))) << 16),
          (y ^= _ = 858993459 & (((g ^= _) >>> 2) ^ y)),
          (y ^= _ = 16711935 & (((g ^= _ << 2) >>> 8) ^ y)),
          (y =
            ((y ^= (_ = 1431655765 & ((y >>> 1) ^ (g ^= _ << 8))) << 1) << 1) |
            (y >>> 31)),
          (g = ((g ^= _) << 1) | (g >>> 31));
        for (var v = 0; v < $; v += 3) {
          for (var m = s[v + 1], C = s[v + 2], E = s[v]; E != m; E += C) {
            var S = g ^ e[E],
              T = ((g >>> 4) | (g << 28)) ^ e[E + 1];
            (_ = y),
              (y = g),
              (g =
                _ ^
                (c[(S >>> 24) & 63] |
                  l[(S >>> 16) & 63] |
                  f[(S >>> 8) & 63] |
                  d[63 & S] |
                  o[(T >>> 24) & 63] |
                  u[(T >>> 16) & 63] |
                  p[(T >>> 8) & 63] |
                  h[63 & T]));
          }
          (_ = y), (y = g), (g = _);
        }
        (g = (g >>> 1) | (g << 31)),
          (g ^= _ = 1431655765 & (((y = (y >>> 1) | (y << 31)) >>> 1) ^ g)),
          (g ^= (_ = 16711935 & ((g >>> 8) ^ (y ^= _ << 1))) << 8),
          (g ^= (_ = 858993459 & ((g >>> 2) ^ (y ^= _))) << 2),
          (g ^= _ = 65535 & (((y ^= _) >>> 16) ^ g)),
          (g ^= _ = 252645135 & (((y ^= _ << 16) >>> 4) ^ g)),
          (y ^= _ << 4),
          (n[0] = y),
          (n[1] = g);
      }
      function $(e) {
        var r,
          n = "DES-" + ((e = e || {}).mode || "CBC").toUpperCase(),
          s = (r = e.decrypt
            ? a.cipher.createDecipher(n, e.key)
            : a.cipher.createCipher(n, e.key)).start;
        return (
          (r.start = function (e, n) {
            var o = null;
            n instanceof a.util.ByteBuffer && ((o = n), (n = {})),
              ((n = n || {}).output = o),
              (n.iv = e),
              s.call(r, n);
          }),
          r
        );
      }
    },
    function (e, r, n) {
      var a = n(0);
      if ((n(3), n(12), n(6), n(26), n(27), n(2), n(1), void 0 === s))
        var s = a.jsbn.BigInteger;
      var o = a.util.isNodejs ? n(16) : null,
        c = a.asn1,
        u = a.util;
      (a.pki = a.pki || {}), (e.exports = a.pki.rsa = a.rsa = a.rsa || {});
      var l = a.pki,
        p = [6, 4, 2, 4, 2, 4, 6, 2],
        f = {
          name: "PrivateKeyInfo",
          tagClass: c.Class.UNIVERSAL,
          type: c.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "PrivateKeyInfo.version",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyVersion",
            },
            {
              name: "PrivateKeyInfo.privateKeyAlgorithm",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "AlgorithmIdentifier.algorithm",
                  tagClass: c.Class.UNIVERSAL,
                  type: c.Type.OID,
                  constructed: !1,
                  capture: "privateKeyOid",
                },
              ],
            },
            {
              name: "PrivateKeyInfo",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.OCTETSTRING,
              constructed: !1,
              capture: "privateKey",
            },
          ],
        },
        h = {
          name: "RSAPrivateKey",
          tagClass: c.Class.UNIVERSAL,
          type: c.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "RSAPrivateKey.version",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyVersion",
            },
            {
              name: "RSAPrivateKey.modulus",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyModulus",
            },
            {
              name: "RSAPrivateKey.publicExponent",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyPublicExponent",
            },
            {
              name: "RSAPrivateKey.privateExponent",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyPrivateExponent",
            },
            {
              name: "RSAPrivateKey.prime1",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyPrime1",
            },
            {
              name: "RSAPrivateKey.prime2",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyPrime2",
            },
            {
              name: "RSAPrivateKey.exponent1",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyExponent1",
            },
            {
              name: "RSAPrivateKey.exponent2",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyExponent2",
            },
            {
              name: "RSAPrivateKey.coefficient",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "privateKeyCoefficient",
            },
          ],
        },
        d = {
          name: "RSAPublicKey",
          tagClass: c.Class.UNIVERSAL,
          type: c.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "RSAPublicKey.modulus",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "publicKeyModulus",
            },
            {
              name: "RSAPublicKey.exponent",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.INTEGER,
              constructed: !1,
              capture: "publicKeyExponent",
            },
          ],
        },
        _ = (a.pki.rsa.publicKeyValidator = {
          name: "SubjectPublicKeyInfo",
          tagClass: c.Class.UNIVERSAL,
          type: c.Type.SEQUENCE,
          constructed: !0,
          captureAsn1: "subjectPublicKeyInfo",
          value: [
            {
              name: "SubjectPublicKeyInfo.AlgorithmIdentifier",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "AlgorithmIdentifier.algorithm",
                  tagClass: c.Class.UNIVERSAL,
                  type: c.Type.OID,
                  constructed: !1,
                  capture: "publicKeyOid",
                },
              ],
            },
            {
              name: "SubjectPublicKeyInfo.subjectPublicKey",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.BITSTRING,
              constructed: !1,
              value: [
                {
                  name: "SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey",
                  tagClass: c.Class.UNIVERSAL,
                  type: c.Type.SEQUENCE,
                  constructed: !0,
                  optional: !0,
                  captureAsn1: "rsaPublicKey",
                },
              ],
            },
          ],
        }),
        $ = {
          name: "DigestInfo",
          tagClass: c.Class.UNIVERSAL,
          type: c.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "DigestInfo.DigestAlgorithm",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "DigestInfo.DigestAlgorithm.algorithmIdentifier",
                  tagClass: c.Class.UNIVERSAL,
                  type: c.Type.OID,
                  constructed: !1,
                  capture: "algorithmIdentifier",
                },
                {
                  name: "DigestInfo.DigestAlgorithm.parameters",
                  tagClass: c.Class.UNIVERSAL,
                  type: c.Type.NULL,
                  capture: "parameters",
                  optional: !0,
                  constructed: !1,
                },
              ],
            },
            {
              name: "DigestInfo.digest",
              tagClass: c.Class.UNIVERSAL,
              type: c.Type.OCTETSTRING,
              constructed: !1,
              capture: "digest",
            },
          ],
        },
        y = function (e) {
          if (!(e.algorithm in l.oids)) {
            var r,
              n = Error("Unknown message digest algorithm.");
            throw ((n.algorithm = e.algorithm), n);
          }
          r = l.oids[e.algorithm];
          var a = c.oidToDer(r).getBytes(),
            s = c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, []),
            o = c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, []);
          o.value.push(c.create(c.Class.UNIVERSAL, c.Type.OID, !1, a)),
            o.value.push(c.create(c.Class.UNIVERSAL, c.Type.NULL, !1, ""));
          var u = c.create(
            c.Class.UNIVERSAL,
            c.Type.OCTETSTRING,
            !1,
            e.digest().getBytes()
          );
          return s.value.push(o), s.value.push(u), c.toDer(s).getBytes();
        },
        g = function (e, r, n) {
          if (n) return e.modPow(r.e, r.n);
          if (!r.p || !r.q) return e.modPow(r.d, r.n);
          r.dP || (r.dP = r.d.mod(r.p.subtract(s.ONE))),
            r.dQ || (r.dQ = r.d.mod(r.q.subtract(s.ONE))),
            r.qInv || (r.qInv = r.q.modInverse(r.p));
          do
            o = new s(
              a.util.bytesToHex(a.random.getBytes(r.n.bitLength() / 8)),
              16
            );
          while (o.compareTo(r.n) >= 0 || !o.gcd(r.n).equals(s.ONE));
          for (
            var o,
              c = (e = e.multiply(o.modPow(r.e, r.n)).mod(r.n))
                .mod(r.p)
                .modPow(r.dP, r.p),
              u = e.mod(r.q).modPow(r.dQ, r.q);
            0 > c.compareTo(u);

          )
            c = c.add(r.p);
          return c
            .subtract(u)
            .multiply(r.qInv)
            .mod(r.p)
            .multiply(r.q)
            .add(u)
            .multiply(o.modInverse(r.n))
            .mod(r.n);
        };
      function v(e, r, n) {
        var s = a.util.createBuffer(),
          o = Math.ceil(r.n.bitLength() / 8);
        if (e.length > o - 11) {
          var c = Error("Message is too long for PKCS#1 v1.5 padding.");
          throw ((c.length = e.length), (c.max = o - 11), c);
        }
        s.putByte(0), s.putByte(n);
        var u,
          l = o - 3 - e.length;
        if (0 === n || 1 === n) {
          u = 0 === n ? 0 : 255;
          for (var p = 0; p < l; ++p) s.putByte(u);
        } else
          for (; l > 0; ) {
            var f = 0,
              h = a.random.getBytes(l);
            for (p = 0; p < l; ++p)
              0 === (u = h.charCodeAt(p)) ? ++f : s.putByte(u);
            l = f;
          }
        return s.putByte(0), s.putBytes(e), s;
      }
      function m(e, r, n, s) {
        var o = Math.ceil(r.n.bitLength() / 8),
          c = a.util.createBuffer(e),
          u = c.getByte(),
          l = c.getByte();
        if (
          0 !== u ||
          (n && 0 !== l && 1 !== l) ||
          (!n && 2 != l) ||
          (n && 0 === l && void 0 === s)
        )
          throw Error("Encryption block is invalid.");
        var p = 0;
        if (0 === l) {
          p = o - 3 - s;
          for (var f = 0; f < p; ++f)
            if (0 !== c.getByte()) throw Error("Encryption block is invalid.");
        } else if (1 === l)
          for (p = 0; c.length() > 1; ) {
            if (255 !== c.getByte()) {
              --c.read;
              break;
            }
            ++p;
          }
        else if (2 === l)
          for (p = 0; c.length() > 1; ) {
            if (0 === c.getByte()) {
              --c.read;
              break;
            }
            ++p;
          }
        if (0 !== c.getByte() || p !== o - 3 - c.length())
          throw Error("Encryption block is invalid.");
        return c.getBytes();
      }
      function C(e) {
        var r = e.toString(16);
        r[0] >= "8" && (r = "00" + r);
        var n = a.util.hexToBytes(r);
        return n.length > 1 &&
          ((0 === n.charCodeAt(0) && 0 == (128 & n.charCodeAt(1))) ||
            (255 === n.charCodeAt(0) && 128 == (128 & n.charCodeAt(1))))
          ? n.substr(1)
          : n;
      }
      function E(e) {
        return e <= 100
          ? 27
          : e <= 150
          ? 18
          : e <= 200
          ? 15
          : e <= 250
          ? 12
          : e <= 300
          ? 9
          : e <= 350
          ? 8
          : e <= 400
          ? 7
          : e <= 500
          ? 6
          : e <= 600
          ? 5
          : e <= 800
          ? 4
          : e <= 1250
          ? 3
          : 2;
      }
      function S(e) {
        return a.util.isNodejs && "function" == typeof o[e];
      }
      function T(e) {
        return (
          void 0 !== u.globalScope &&
          "object" == typeof u.globalScope.crypto &&
          "object" == typeof u.globalScope.crypto.subtle &&
          "function" == typeof u.globalScope.crypto.subtle[e]
        );
      }
      function B(e) {
        return (
          void 0 !== u.globalScope &&
          "object" == typeof u.globalScope.msCrypto &&
          "object" == typeof u.globalScope.msCrypto.subtle &&
          "function" == typeof u.globalScope.msCrypto.subtle[e]
        );
      }
      function I(e) {
        for (
          var r = a.util.hexToBytes(e.toString(16)),
            n = new Uint8Array(r.length),
            s = 0;
          s < r.length;
          ++s
        )
          n[s] = r.charCodeAt(s);
        return n;
      }
      (l.rsa.encrypt = function (e, r, n) {
        var o,
          c = n,
          u = Math.ceil(r.n.bitLength() / 8);
        !1 !== n && !0 !== n
          ? ((c = 2 === n), (o = v(e, r, n)))
          : (o = a.util.createBuffer()).putBytes(e);
        for (
          var l = new s(o.toHex(), 16),
            p = g(l, r, c).toString(16),
            f = a.util.createBuffer(),
            h = u - Math.ceil(p.length / 2);
          h > 0;

        )
          f.putByte(0), --h;
        return f.putBytes(a.util.hexToBytes(p)), f.getBytes();
      }),
        (l.rsa.decrypt = function (e, r, n, o) {
          var c = Math.ceil(r.n.bitLength() / 8);
          if (e.length !== c) {
            var u = Error("Encrypted message length is invalid.");
            throw ((u.length = e.length), (u.expected = c), u);
          }
          var l = new s(a.util.createBuffer(e).toHex(), 16);
          if (l.compareTo(r.n) >= 0)
            throw Error("Encrypted message is invalid.");
          for (
            var p = g(l, r, n).toString(16),
              f = a.util.createBuffer(),
              h = c - Math.ceil(p.length / 2);
            h > 0;

          )
            f.putByte(0), --h;
          return (
            f.putBytes(a.util.hexToBytes(p)),
            !1 !== o ? m(f.getBytes(), r, n) : f.getBytes()
          );
        }),
        (l.rsa.createKeyPairGenerationState = function (e, r, n) {
          "string" == typeof e && (e = parseInt(e, 10)), (e = e || 2048);
          var o,
            c = (n = n || {}).prng || a.random,
            u = n.algorithm || "PRIMEINC";
          if ("PRIMEINC" !== u)
            throw Error("Invalid key generation algorithm: " + u);
          return (
            (o = {
              algorithm: u,
              state: 0,
              bits: e,
              rng: {
                nextBytes: function (e) {
                  for (
                    var r = c.getBytesSync(e.length), n = 0;
                    n < e.length;
                    ++n
                  )
                    e[n] = r.charCodeAt(n);
                },
              },
              eInt: r || 65537,
              e: new s(null),
              p: null,
              q: null,
              qBits: e >> 1,
              pBits: e - (e >> 1),
              pqState: 0,
              num: null,
              keys: null,
            }).e.fromInt(o.eInt),
            o
          );
        }),
        (l.rsa.stepKeyPairGenerationState = function (e, r) {
          "algorithm" in e || (e.algorithm = "PRIMEINC");
          var n = new s(null);
          n.fromInt(30);
          for (
            var a,
              o = 0,
              c = function (e, r) {
                return e | r;
              },
              u = +new Date(),
              f = 0;
            null === e.keys && (r <= 0 || f < r);

          ) {
            if (0 === e.state) {
              var h = null === e.p ? e.pBits : e.qBits,
                d = h - 1;
              0 === e.pqState
                ? ((e.num = new s(h, e.rng)),
                  e.num.testBit(d) ||
                    e.num.bitwiseTo(s.ONE.shiftLeft(d), c, e.num),
                  e.num.dAddOffset(31 - e.num.mod(n).byteValue(), 0),
                  (o = 0),
                  ++e.pqState)
                : 1 === e.pqState
                ? e.num.bitLength() > h
                  ? (e.pqState = 0)
                  : e.num.isProbablePrime(E(e.num.bitLength()))
                  ? ++e.pqState
                  : e.num.dAddOffset(p[o++ % 8], 0)
                : 2 === e.pqState
                ? (e.pqState =
                    0 === e.num.subtract(s.ONE).gcd(e.e).compareTo(s.ONE)
                      ? 3
                      : 0)
                : 3 === e.pqState &&
                  ((e.pqState = 0),
                  null === e.p ? (e.p = e.num) : (e.q = e.num),
                  null !== e.p && null !== e.q && ++e.state,
                  (e.num = null));
            } else if (1 === e.state)
              0 > e.p.compareTo(e.q) &&
                ((e.num = e.p), (e.p = e.q), (e.q = e.num)),
                ++e.state;
            else if (2 === e.state)
              (e.p1 = e.p.subtract(s.ONE)),
                (e.q1 = e.q.subtract(s.ONE)),
                (e.phi = e.p1.multiply(e.q1)),
                ++e.state;
            else if (3 === e.state)
              0 === e.phi.gcd(e.e).compareTo(s.ONE)
                ? ++e.state
                : ((e.p = null), (e.q = null), (e.state = 0));
            else if (4 === e.state)
              (e.n = e.p.multiply(e.q)),
                e.n.bitLength() === e.bits
                  ? ++e.state
                  : ((e.q = null), (e.state = 0));
            else if (5 === e.state) {
              var _ = e.e.modInverse(e.phi);
              e.keys = {
                privateKey: l.rsa.setPrivateKey(
                  e.n,
                  e.e,
                  _,
                  e.p,
                  e.q,
                  _.mod(e.p1),
                  _.mod(e.q1),
                  e.q.modInverse(e.p)
                ),
                publicKey: l.rsa.setPublicKey(e.n, e.e),
              };
            }
            (f += (a = +new Date()) - u), (u = a);
          }
          return null !== e.keys;
        }),
        (l.rsa.generateKeyPair = function (e, r, n, p) {
          if (
            (1 === arguments.length
              ? "object" == typeof e
                ? ((n = e), (e = void 0))
                : "function" == typeof e && ((p = e), (e = void 0))
              : 2 === arguments.length
              ? "number" == typeof e
                ? "function" == typeof r
                  ? ((p = r), (r = void 0))
                  : "number" != typeof r && ((n = r), (r = void 0))
                : ((n = e), (p = r), (e = void 0), (r = void 0))
              : 3 === arguments.length &&
                ("number" == typeof r
                  ? "function" == typeof n && ((p = n), (n = void 0))
                  : ((p = n), (n = r), (r = void 0))),
            (n = n || {}),
            void 0 === e && (e = n.bits || 2048),
            void 0 === r && (r = n.e || 65537),
            !a.options.usePureJavaScript &&
              !n.prng &&
              e >= 256 &&
              e <= 16384 &&
              (65537 === r || 3 === r))
          ) {
            if (p) {
              if (S("generateKeyPair"))
                return o.generateKeyPair(
                  "rsa",
                  {
                    modulusLength: e,
                    publicExponent: r,
                    publicKeyEncoding: { type: "spki", format: "pem" },
                    privateKeyEncoding: { type: "pkcs8", format: "pem" },
                  },
                  function (e, r, n) {
                    if (e) return p(e);
                    p(null, {
                      privateKey: l.privateKeyFromPem(n),
                      publicKey: l.publicKeyFromPem(r),
                    });
                  }
                );
              if (T("generateKey") && T("exportKey"))
                return u.globalScope.crypto.subtle
                  .generateKey(
                    {
                      name: "RSASSA-PKCS1-v1_5",
                      modulusLength: e,
                      publicExponent: I(r),
                      hash: { name: "SHA-256" },
                    },
                    !0,
                    ["sign", "verify"]
                  )
                  .then(function (e) {
                    return u.globalScope.crypto.subtle.exportKey(
                      "pkcs8",
                      e.privateKey
                    );
                  })
                  .then(void 0, function (e) {
                    p(e);
                  })
                  .then(function (e) {
                    if (e) {
                      var r = l.privateKeyFromAsn1(
                        c.fromDer(a.util.createBuffer(e))
                      );
                      p(null, {
                        privateKey: r,
                        publicKey: l.setRsaPublicKey(r.n, r.e),
                      });
                    }
                  });
              if (B("generateKey") && B("exportKey")) {
                var f = u.globalScope.msCrypto.subtle.generateKey(
                  {
                    name: "RSASSA-PKCS1-v1_5",
                    modulusLength: e,
                    publicExponent: I(r),
                    hash: { name: "SHA-256" },
                  },
                  !0,
                  ["sign", "verify"]
                );
                return (
                  (f.oncomplete = function (e) {
                    var r = e.target.result,
                      n = u.globalScope.msCrypto.subtle.exportKey(
                        "pkcs8",
                        r.privateKey
                      );
                    (n.oncomplete = function (e) {
                      var r = e.target.result,
                        n = l.privateKeyFromAsn1(
                          c.fromDer(a.util.createBuffer(r))
                        );
                      p(null, {
                        privateKey: n,
                        publicKey: l.setRsaPublicKey(n.n, n.e),
                      });
                    }),
                      (n.onerror = function (e) {
                        p(e);
                      });
                  }),
                  void (f.onerror = function (e) {
                    p(e);
                  })
                );
              }
            } else if (S("generateKeyPairSync")) {
              var h = o.generateKeyPairSync("rsa", {
                modulusLength: e,
                publicExponent: r,
                publicKeyEncoding: { type: "spki", format: "pem" },
                privateKeyEncoding: { type: "pkcs8", format: "pem" },
              });
              return {
                privateKey: l.privateKeyFromPem(h.privateKey),
                publicKey: l.publicKeyFromPem(h.publicKey),
              };
            }
          }
          var d = l.rsa.createKeyPairGenerationState(e, r, n);
          if (!p) return l.rsa.stepKeyPairGenerationState(d, 0), d.keys;
          (function e(r, n, o) {
            "function" == typeof n && ((o = n), (n = {}));
            var c = {
              algorithm: {
                name: (n = n || {}).algorithm || "PRIMEINC",
                options: {
                  workers: n.workers || 2,
                  workLoad: n.workLoad || 100,
                  workerScript: n.workerScript,
                },
              },
            };
            function u() {
              p(r.pBits, function (e, n) {
                return e
                  ? o(e)
                  : ((r.p = n), null !== r.q ? f(e, r.q) : void p(r.qBits, f));
              });
            }
            function p(e, r) {
              a.prime.generateProbablePrime(e, c, r);
            }
            function f(e, n) {
              if (e) return o(e);
              if (((r.q = n), 0 > r.p.compareTo(r.q))) {
                var a = r.p;
                (r.p = r.q), (r.q = a);
              }
              if (0 !== r.p.subtract(s.ONE).gcd(r.e).compareTo(s.ONE))
                return (r.p = null), void u();
              if (0 !== r.q.subtract(s.ONE).gcd(r.e).compareTo(s.ONE))
                return (r.q = null), void p(r.qBits, f);
              if (
                ((r.p1 = r.p.subtract(s.ONE)),
                (r.q1 = r.q.subtract(s.ONE)),
                (r.phi = r.p1.multiply(r.q1)),
                0 !== r.phi.gcd(r.e).compareTo(s.ONE))
              )
                return (r.p = r.q = null), void u();
              if (((r.n = r.p.multiply(r.q)), r.n.bitLength() !== r.bits))
                return (r.q = null), void p(r.qBits, f);
              var c = r.e.modInverse(r.phi);
              (r.keys = {
                privateKey: l.rsa.setPrivateKey(
                  r.n,
                  r.e,
                  c,
                  r.p,
                  r.q,
                  c.mod(r.p1),
                  c.mod(r.q1),
                  r.q.modInverse(r.p)
                ),
                publicKey: l.rsa.setPublicKey(r.n, r.e),
              }),
                o(null, r.keys);
            }
            "prng" in n && (c.prng = n.prng), u();
          })(d, n, p);
        }),
        (l.setRsaPublicKey = l.rsa.setPublicKey =
          function (e, r) {
            var n = {
              n: e,
              e: r,
              encrypt: function (e, r, s) {
                if (
                  ("string" == typeof r
                    ? (r = r.toUpperCase())
                    : void 0 === r && (r = "RSAES-PKCS1-V1_5"),
                  "RSAES-PKCS1-V1_5" === r)
                )
                  r = {
                    encode: function (e, r, n) {
                      return v(e, r, 2).getBytes();
                    },
                  };
                else if ("RSA-OAEP" === r || "RSAES-OAEP" === r)
                  r = {
                    encode: function (e, r) {
                      return a.pkcs1.encode_rsa_oaep(r, e, s);
                    },
                  };
                else if (-1 !== ["RAW", "NONE", "NULL", null].indexOf(r))
                  r = {
                    encode: function (e) {
                      return e;
                    },
                  };
                else if ("string" == typeof r)
                  throw Error('Unsupported encryption scheme: "' + r + '".');
                var o = r.encode(e, n, !0);
                return l.rsa.encrypt(o, n, !0);
              },
              verify: function (e, r, s, o) {
                "string" == typeof s
                  ? (s = s.toUpperCase())
                  : void 0 === s && (s = "RSASSA-PKCS1-V1_5"),
                  void 0 === o && (o = { _parseAllDigestBytes: !0 }),
                  "_parseAllDigestBytes" in o || (o._parseAllDigestBytes = !0),
                  "RSASSA-PKCS1-V1_5" === s
                    ? (s = {
                        verify: function (e, r) {
                          r = m(r, n, !0);
                          var s = c.fromDer(r, {
                              parseAllBytes: o._parseAllDigestBytes,
                            }),
                            u = {},
                            l = [];
                          if (!c.validate(s, $, u, l))
                            throw (
                              (((p = Error(
                                "ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value."
                              )).errors = l),
                              p)
                            );
                          var p,
                            f = c.derToOid(u.algorithmIdentifier);
                          if (
                            f !== a.oids.md2 &&
                            f !== a.oids.md5 &&
                            f !== a.oids.sha1 &&
                            f !== a.oids.sha224 &&
                            f !== a.oids.sha256 &&
                            f !== a.oids.sha384 &&
                            f !== a.oids.sha512 &&
                            f !== a.oids["sha512-224"] &&
                            f !== a.oids["sha512-256"]
                          )
                            throw (
                              (((p = Error(
                                "Unknown RSASSA-PKCS1-v1_5 DigestAlgorithm identifier."
                              )).oid = f),
                              p)
                            );
                          if (
                            (f === a.oids.md2 || f === a.oids.md5) &&
                            !("parameters" in u)
                          )
                            throw Error(
                              "ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value. Missing algorithm identifer NULL parameters."
                            );
                          return e === u.digest;
                        },
                      })
                    : ("NONE" !== s && "NULL" !== s && null !== s) ||
                      (s = {
                        verify: function (e, r) {
                          return e === (r = m(r, n, !0));
                        },
                      });
                var u = l.rsa.decrypt(r, n, !0, !1);
                return s.verify(e, u, n.n.bitLength());
              },
            };
            return n;
          }),
        (l.setRsaPrivateKey = l.rsa.setPrivateKey =
          function (e, r, n, s, o, c, u, p) {
            var f = {
              n: e,
              e: r,
              d: n,
              p: s,
              q: o,
              dP: c,
              dQ: u,
              qInv: p,
              decrypt: function (e, r, n) {
                "string" == typeof r
                  ? (r = r.toUpperCase())
                  : void 0 === r && (r = "RSAES-PKCS1-V1_5");
                var s = l.rsa.decrypt(e, f, !1, !1);
                if ("RSAES-PKCS1-V1_5" === r) r = { decode: m };
                else if ("RSA-OAEP" === r || "RSAES-OAEP" === r)
                  r = {
                    decode: function (e, r) {
                      return a.pkcs1.decode_rsa_oaep(r, e, n);
                    },
                  };
                else {
                  if (-1 === ["RAW", "NONE", "NULL", null].indexOf(r))
                    throw Error('Unsupported encryption scheme: "' + r + '".');
                  r = {
                    decode: function (e) {
                      return e;
                    },
                  };
                }
                return r.decode(s, f, !1);
              },
              sign: function (e, r) {
                var n = !1;
                "string" == typeof r && (r = r.toUpperCase()),
                  void 0 === r || "RSASSA-PKCS1-V1_5" === r
                    ? ((r = { encode: y }), (n = 1))
                    : ("NONE" !== r && "NULL" !== r && null !== r) ||
                      ((r = {
                        encode: function () {
                          return e;
                        },
                      }),
                      (n = 1));
                var a = r.encode(e, f.n.bitLength());
                return l.rsa.encrypt(a, f, n);
              },
            };
            return f;
          }),
        (l.wrapRsaPrivateKey = function (e) {
          return c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, [
            c.create(
              c.Class.UNIVERSAL,
              c.Type.INTEGER,
              !1,
              c.integerToDer(0).getBytes()
            ),
            c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, [
              c.create(
                c.Class.UNIVERSAL,
                c.Type.OID,
                !1,
                c.oidToDer(l.oids.rsaEncryption).getBytes()
              ),
              c.create(c.Class.UNIVERSAL, c.Type.NULL, !1, ""),
            ]),
            c.create(
              c.Class.UNIVERSAL,
              c.Type.OCTETSTRING,
              !1,
              c.toDer(e).getBytes()
            ),
          ]);
        }),
        (l.privateKeyFromAsn1 = function (e) {
          var r,
            n,
            o,
            u,
            p,
            d,
            _,
            $,
            y = {},
            g = [];
          if (
            (c.validate(e, f, y, g) &&
              (e = c.fromDer(a.util.createBuffer(y.privateKey))),
            (y = {}),
            (g = []),
            !c.validate(e, h, y, g))
          ) {
            var v = Error(
              "Cannot read private key. ASN.1 object does not contain an RSAPrivateKey."
            );
            throw ((v.errors = g), v);
          }
          return (
            (r = a.util.createBuffer(y.privateKeyModulus).toHex()),
            (n = a.util.createBuffer(y.privateKeyPublicExponent).toHex()),
            (o = a.util.createBuffer(y.privateKeyPrivateExponent).toHex()),
            (u = a.util.createBuffer(y.privateKeyPrime1).toHex()),
            (p = a.util.createBuffer(y.privateKeyPrime2).toHex()),
            (d = a.util.createBuffer(y.privateKeyExponent1).toHex()),
            (_ = a.util.createBuffer(y.privateKeyExponent2).toHex()),
            ($ = a.util.createBuffer(y.privateKeyCoefficient).toHex()),
            l.setRsaPrivateKey(
              new s(r, 16),
              new s(n, 16),
              new s(o, 16),
              new s(u, 16),
              new s(p, 16),
              new s(d, 16),
              new s(_, 16),
              new s($, 16)
            )
          );
        }),
        (l.privateKeyToAsn1 = l.privateKeyToRSAPrivateKey =
          function (e) {
            return c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, [
              c.create(
                c.Class.UNIVERSAL,
                c.Type.INTEGER,
                !1,
                c.integerToDer(0).getBytes()
              ),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.n)),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.e)),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.d)),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.p)),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.q)),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.dP)),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.dQ)),
              c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.qInv)),
            ]);
          }),
        (l.publicKeyFromAsn1 = function (e) {
          var r = {},
            n = [];
          if (c.validate(e, _, r, n)) {
            var o,
              u = c.derToOid(r.publicKeyOid);
            if (u !== l.oids.rsaEncryption)
              throw (
                (((o = Error("Cannot read public key. Unknown OID.")).oid = u),
                o)
              );
            e = r.rsaPublicKey;
          }
          if (((n = []), !c.validate(e, d, r, n)))
            throw (
              (((o = Error(
                "Cannot read public key. ASN.1 object does not contain an RSAPublicKey."
              )).errors = n),
              o)
            );
          var p = a.util.createBuffer(r.publicKeyModulus).toHex(),
            f = a.util.createBuffer(r.publicKeyExponent).toHex();
          return l.setRsaPublicKey(new s(p, 16), new s(f, 16));
        }),
        (l.publicKeyToAsn1 = l.publicKeyToSubjectPublicKeyInfo =
          function (e) {
            return c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, [
              c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, [
                c.create(
                  c.Class.UNIVERSAL,
                  c.Type.OID,
                  !1,
                  c.oidToDer(l.oids.rsaEncryption).getBytes()
                ),
                c.create(c.Class.UNIVERSAL, c.Type.NULL, !1, ""),
              ]),
              c.create(c.Class.UNIVERSAL, c.Type.BITSTRING, !1, [
                l.publicKeyToRSAPublicKey(e),
              ]),
            ]);
          }),
        (l.publicKeyToRSAPublicKey = function (e) {
          return c.create(c.Class.UNIVERSAL, c.Type.SEQUENCE, !0, [
            c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.n)),
            c.create(c.Class.UNIVERSAL, c.Type.INTEGER, !1, C(e.e)),
          ]);
        });
    },
    function (e, r, n) {
      var a,
        s = n(0);
      function o(e, r, n) {
        (this.data = []),
          null != e &&
            ("number" == typeof e
              ? this.fromNumber(e, r, n)
              : null == r && "string" != typeof e
              ? this.fromString(e, 256)
              : this.fromString(e, r));
      }
      function c() {
        return new o(null);
      }
      function u(e, r, n, a, s, o) {
        for (var c = 16383 & r, u = r >> 14; --o >= 0; ) {
          var l = 16383 & this.data[e],
            p = this.data[e++] >> 14,
            f = u * l + p * c;
          (s =
            ((l = c * l + ((16383 & f) << 14) + n.data[a] + s) >> 28) +
            (f >> 14) +
            u * p),
            (n.data[a++] = 268435455 & l);
        }
        return s;
      }
      (e.exports = s.jsbn = s.jsbn || {}),
        (s.jsbn.BigInteger = o),
        "undefined" == typeof navigator
          ? ((o.prototype.am = u), (a = 28))
          : "Microsoft Internet Explorer" == navigator.appName
          ? ((o.prototype.am = function (e, r, n, a, s, o) {
              for (var c = 32767 & r, u = r >> 15; --o >= 0; ) {
                var l = 32767 & this.data[e],
                  p = this.data[e++] >> 15,
                  f = u * l + p * c;
                (s =
                  ((l =
                    c * l +
                    ((32767 & f) << 15) +
                    n.data[a] +
                    (1073741823 & s)) >>>
                    30) +
                  (f >>> 15) +
                  u * p +
                  (s >>> 30)),
                  (n.data[a++] = 1073741823 & l);
              }
              return s;
            }),
            (a = 30))
          : "Netscape" != navigator.appName
          ? ((o.prototype.am = function (e, r, n, a, s, o) {
              for (; --o >= 0; ) {
                var c = r * this.data[e++] + n.data[a] + s;
                (s = Math.floor(c / 67108864)), (n.data[a++] = 67108863 & c);
              }
              return s;
            }),
            (a = 26))
          : ((o.prototype.am = u), (a = 28)),
        (o.prototype.DB = a),
        (o.prototype.DM = (1 << a) - 1),
        (o.prototype.DV = 1 << a),
        (o.prototype.FV = 4503599627370496),
        (o.prototype.F1 = 52 - a),
        (o.prototype.F2 = 2 * a - 52);
      var l,
        p,
        f = [];
      for (l = 48, p = 0; p <= 9; ++p) f[l++] = p;
      for (l = 97, p = 10; p < 36; ++p) f[l++] = p;
      for (l = 65, p = 10; p < 36; ++p) f[l++] = p;
      function h(e) {
        return "0123456789abcdefghijklmnopqrstuvwxyz".charAt(e);
      }
      function d(e, r) {
        var n = f[e.charCodeAt(r)];
        return null == n ? -1 : n;
      }
      function _(e) {
        var r = c();
        return r.fromInt(e), r;
      }
      function $(e) {
        var r,
          n = 1;
        return (
          0 != (r = e >>> 16) && ((e = r), (n += 16)),
          0 != (r = e >> 8) && ((e = r), (n += 8)),
          0 != (r = e >> 4) && ((e = r), (n += 4)),
          0 != (r = e >> 2) && ((e = r), (n += 2)),
          0 != (r = e >> 1) && ((e = r), (n += 1)),
          n
        );
      }
      function y(e) {
        this.m = e;
      }
      function g(e) {
        (this.m = e),
          (this.mp = e.invDigit()),
          (this.mpl = 32767 & this.mp),
          (this.mph = this.mp >> 15),
          (this.um = (1 << (e.DB - 15)) - 1),
          (this.mt2 = 2 * e.t);
      }
      function v(e, r) {
        return e & r;
      }
      function m(e, r) {
        return e | r;
      }
      function C(e, r) {
        return e ^ r;
      }
      function E(e, r) {
        return e & ~r;
      }
      function S(e) {
        if (0 == e) return -1;
        var r = 0;
        return (
          0 == (65535 & e) && ((e >>= 16), (r += 16)),
          0 == (255 & e) && ((e >>= 8), (r += 8)),
          0 == (15 & e) && ((e >>= 4), (r += 4)),
          0 == (3 & e) && ((e >>= 2), (r += 2)),
          0 == (1 & e) && ++r,
          r
        );
      }
      function T(e) {
        for (var r = 0; 0 != e; ) (e &= e - 1), ++r;
        return r;
      }
      function B() {}
      function I(e) {
        return e;
      }
      function A(e) {
        (this.r2 = c()),
          (this.q3 = c()),
          o.ONE.dlShiftTo(2 * e.t, this.r2),
          (this.mu = this.r2.divide(e)),
          (this.m = e);
      }
      (y.prototype.convert = function (e) {
        return e.s < 0 || e.compareTo(this.m) >= 0 ? e.mod(this.m) : e;
      }),
        (y.prototype.revert = function (e) {
          return e;
        }),
        (y.prototype.reduce = function (e) {
          e.divRemTo(this.m, null, e);
        }),
        (y.prototype.mulTo = function (e, r, n) {
          e.multiplyTo(r, n), this.reduce(n);
        }),
        (y.prototype.sqrTo = function (e, r) {
          e.squareTo(r), this.reduce(r);
        }),
        (g.prototype.convert = function (e) {
          var r = c();
          return (
            e.abs().dlShiftTo(this.m.t, r),
            r.divRemTo(this.m, null, r),
            e.s < 0 && r.compareTo(o.ZERO) > 0 && this.m.subTo(r, r),
            r
          );
        }),
        (g.prototype.revert = function (e) {
          var r = c();
          return e.copyTo(r), this.reduce(r), r;
        }),
        (g.prototype.reduce = function (e) {
          for (; e.t <= this.mt2; ) e.data[e.t++] = 0;
          for (var r = 0; r < this.m.t; ++r) {
            var n = 32767 & e.data[r],
              a =
                (n * this.mpl +
                  (((n * this.mph + (e.data[r] >> 15) * this.mpl) & this.um) <<
                    15)) &
                e.DM;
            for (
              n = r + this.m.t, e.data[n] += this.m.am(0, a, e, r, 0, this.m.t);
              e.data[n] >= e.DV;

            )
              (e.data[n] -= e.DV), e.data[++n]++;
          }
          e.clamp(),
            e.drShiftTo(this.m.t, e),
            e.compareTo(this.m) >= 0 && e.subTo(this.m, e);
        }),
        (g.prototype.mulTo = function (e, r, n) {
          e.multiplyTo(r, n), this.reduce(n);
        }),
        (g.prototype.sqrTo = function (e, r) {
          e.squareTo(r), this.reduce(r);
        }),
        (o.prototype.copyTo = function (e) {
          for (var r = this.t - 1; r >= 0; --r) e.data[r] = this.data[r];
          (e.t = this.t), (e.s = this.s);
        }),
        (o.prototype.fromInt = function (e) {
          (this.t = 1),
            (this.s = e < 0 ? -1 : 0),
            e > 0
              ? (this.data[0] = e)
              : e < -1
              ? (this.data[0] = e + this.DV)
              : (this.t = 0);
        }),
        (o.prototype.fromString = function (e, r) {
          var n;
          if (16 == r) n = 4;
          else if (8 == r) n = 3;
          else if (256 == r) n = 8;
          else if (2 == r) n = 1;
          else if (32 == r) n = 5;
          else {
            if (4 != r) return void this.fromRadix(e, r);
            n = 2;
          }
          (this.t = 0), (this.s = 0);
          for (var a = e.length, s = !1, c = 0; --a >= 0; ) {
            var u = 8 == n ? 255 & e[a] : d(e, a);
            u < 0
              ? "-" == e.charAt(a) && (s = !0)
              : ((s = !1),
                0 == c
                  ? (this.data[this.t++] = u)
                  : c + n > this.DB
                  ? ((this.data[this.t - 1] |=
                      (u & ((1 << (this.DB - c)) - 1)) << c),
                    (this.data[this.t++] = u >> (this.DB - c)))
                  : (this.data[this.t - 1] |= u << c),
                (c += n) >= this.DB && (c -= this.DB));
          }
          8 == n &&
            0 != (128 & e[0]) &&
            ((this.s = -1),
            c > 0 &&
              (this.data[this.t - 1] |= ((1 << (this.DB - c)) - 1) << c)),
            this.clamp(),
            s && o.ZERO.subTo(this, this);
        }),
        (o.prototype.clamp = function () {
          for (
            var e = this.s & this.DM;
            this.t > 0 && this.data[this.t - 1] == e;

          )
            --this.t;
        }),
        (o.prototype.dlShiftTo = function (e, r) {
          var n;
          for (n = this.t - 1; n >= 0; --n) r.data[n + e] = this.data[n];
          for (n = e - 1; n >= 0; --n) r.data[n] = 0;
          (r.t = this.t + e), (r.s = this.s);
        }),
        (o.prototype.drShiftTo = function (e, r) {
          for (var n = e; n < this.t; ++n) r.data[n - e] = this.data[n];
          (r.t = Math.max(this.t - e, 0)), (r.s = this.s);
        }),
        (o.prototype.lShiftTo = function (e, r) {
          var n,
            a = e % this.DB,
            s = this.DB - a,
            o = (1 << s) - 1,
            c = Math.floor(e / this.DB),
            u = (this.s << a) & this.DM;
          for (n = this.t - 1; n >= 0; --n)
            (r.data[n + c + 1] = (this.data[n] >> s) | u),
              (u = (this.data[n] & o) << a);
          for (n = c - 1; n >= 0; --n) r.data[n] = 0;
          (r.data[c] = u), (r.t = this.t + c + 1), (r.s = this.s), r.clamp();
        }),
        (o.prototype.rShiftTo = function (e, r) {
          r.s = this.s;
          var n = Math.floor(e / this.DB);
          if (n >= this.t) r.t = 0;
          else {
            var a = e % this.DB,
              s = this.DB - a,
              o = (1 << a) - 1;
            r.data[0] = this.data[n] >> a;
            for (var c = n + 1; c < this.t; ++c)
              (r.data[c - n - 1] |= (this.data[c] & o) << s),
                (r.data[c - n] = this.data[c] >> a);
            a > 0 && (r.data[this.t - n - 1] |= (this.s & o) << s),
              (r.t = this.t - n),
              r.clamp();
          }
        }),
        (o.prototype.subTo = function (e, r) {
          for (var n = 0, a = 0, s = Math.min(e.t, this.t); n < s; )
            (a += this.data[n] - e.data[n]),
              (r.data[n++] = a & this.DM),
              (a >>= this.DB);
          if (e.t < this.t) {
            for (a -= e.s; n < this.t; )
              (a += this.data[n]), (r.data[n++] = a & this.DM), (a >>= this.DB);
            a += this.s;
          } else {
            for (a += this.s; n < e.t; )
              (a -= e.data[n]), (r.data[n++] = a & this.DM), (a >>= this.DB);
            a -= e.s;
          }
          (r.s = a < 0 ? -1 : 0),
            a < -1 ? (r.data[n++] = this.DV + a) : a > 0 && (r.data[n++] = a),
            (r.t = n),
            r.clamp();
        }),
        (o.prototype.multiplyTo = function (e, r) {
          var n = this.abs(),
            a = e.abs(),
            s = n.t;
          for (r.t = s + a.t; --s >= 0; ) r.data[s] = 0;
          for (s = 0; s < a.t; ++s)
            r.data[s + n.t] = n.am(0, a.data[s], r, s, 0, n.t);
          (r.s = 0), r.clamp(), this.s != e.s && o.ZERO.subTo(r, r);
        }),
        (o.prototype.squareTo = function (e) {
          for (var r = this.abs(), n = (e.t = 2 * r.t); --n >= 0; )
            e.data[n] = 0;
          for (n = 0; n < r.t - 1; ++n) {
            var a = r.am(n, r.data[n], e, 2 * n, 0, 1);
            (e.data[n + r.t] += r.am(
              n + 1,
              2 * r.data[n],
              e,
              2 * n + 1,
              a,
              r.t - n - 1
            )) >= r.DV &&
              ((e.data[n + r.t] -= r.DV), (e.data[n + r.t + 1] = 1));
          }
          e.t > 0 && (e.data[e.t - 1] += r.am(n, r.data[n], e, 2 * n, 0, 1)),
            (e.s = 0),
            e.clamp();
        }),
        (o.prototype.divRemTo = function (e, r, n) {
          var a = e.abs();
          if (!(a.t <= 0)) {
            var s = this.abs();
            if (s.t < a.t)
              return (
                null != r && r.fromInt(0), void (null != n && this.copyTo(n))
              );
            null == n && (n = c());
            var u = c(),
              l = this.s,
              p = e.s,
              f = this.DB - $(a.data[a.t - 1]);
            f > 0
              ? (a.lShiftTo(f, u), s.lShiftTo(f, n))
              : (a.copyTo(u), s.copyTo(n));
            var h = u.t,
              d = u.data[h - 1];
            if (0 != d) {
              var _ =
                  d * (1 << this.F1) + (h > 1 ? u.data[h - 2] >> this.F2 : 0),
                y = this.FV / _,
                g = (1 << this.F1) / _,
                v = 1 << this.F2,
                m = n.t,
                C = m - h,
                E = null == r ? c() : r;
              for (
                u.dlShiftTo(C, E),
                  n.compareTo(E) >= 0 && ((n.data[n.t++] = 1), n.subTo(E, n)),
                  o.ONE.dlShiftTo(h, E),
                  E.subTo(u, u);
                u.t < h;

              )
                u.data[u.t++] = 0;
              for (; --C >= 0; ) {
                var S =
                  n.data[--m] == d
                    ? this.DM
                    : Math.floor(n.data[m] * y + (n.data[m - 1] + v) * g);
                if ((n.data[m] += u.am(0, S, n, C, 0, h)) < S)
                  for (u.dlShiftTo(C, E), n.subTo(E, n); n.data[m] < --S; )
                    n.subTo(E, n);
              }
              null != r && (n.drShiftTo(h, r), l != p && o.ZERO.subTo(r, r)),
                (n.t = h),
                n.clamp(),
                f > 0 && n.rShiftTo(f, n),
                l < 0 && o.ZERO.subTo(n, n);
            }
          }
        }),
        (o.prototype.invDigit = function () {
          if (this.t < 1) return 0;
          var e = this.data[0];
          if (0 == (1 & e)) return 0;
          var r = 3 & e;
          return (r =
            ((r =
              ((r =
                ((r = (r * (2 - (15 & e) * r)) & 15) * (2 - (255 & e) * r)) &
                255) *
                (2 - (((65535 & e) * r) & 65535))) &
              65535) *
              (2 - ((e * r) % this.DV))) %
            this.DV) > 0
            ? this.DV - r
            : -r;
        }),
        (o.prototype.isEven = function () {
          return 0 == (this.t > 0 ? 1 & this.data[0] : this.s);
        }),
        (o.prototype.exp = function (e, r) {
          if (e > 4294967295 || e < 1) return o.ONE;
          var n = c(),
            a = c(),
            s = r.convert(this),
            u = $(e) - 1;
          for (s.copyTo(n); --u >= 0; )
            if ((r.sqrTo(n, a), (e & (1 << u)) > 0)) r.mulTo(a, s, n);
            else {
              var l = n;
              (n = a), (a = l);
            }
          return r.revert(n);
        }),
        (o.prototype.toString = function (e) {
          if (this.s < 0) return "-" + this.negate().toString(e);
          if (16 == e) r = 4;
          else if (8 == e) r = 3;
          else if (2 == e) r = 1;
          else if (32 == e) r = 5;
          else {
            if (4 != e) return this.toRadix(e);
            r = 2;
          }
          var r,
            n,
            a = (1 << r) - 1,
            s = !1,
            o = "",
            c = this.t,
            u = this.DB - ((c * this.DB) % r);
          if (c-- > 0)
            for (
              u < this.DB &&
              (n = this.data[c] >> u) > 0 &&
              ((s = !0), (o = h(n)));
              c >= 0;

            )
              u < r
                ? ((n = (this.data[c] & ((1 << u) - 1)) << (r - u)),
                  (n |= this.data[--c] >> (u += this.DB - r)))
                : ((n = (this.data[c] >> (u -= r)) & a),
                  u <= 0 && ((u += this.DB), --c)),
                n > 0 && (s = !0),
                s && (o += h(n));
          return s ? o : "0";
        }),
        (o.prototype.negate = function () {
          var e = c();
          return o.ZERO.subTo(this, e), e;
        }),
        (o.prototype.abs = function () {
          return this.s < 0 ? this.negate() : this;
        }),
        (o.prototype.compareTo = function (e) {
          var r = this.s - e.s;
          if (0 != r) return r;
          var n = this.t;
          if (0 != (r = n - e.t)) return this.s < 0 ? -r : r;
          for (; --n >= 0; ) if (0 != (r = this.data[n] - e.data[n])) return r;
          return 0;
        }),
        (o.prototype.bitLength = function () {
          return this.t <= 0
            ? 0
            : this.DB * (this.t - 1) +
                $(this.data[this.t - 1] ^ (this.s & this.DM));
        }),
        (o.prototype.mod = function (e) {
          var r = c();
          return (
            this.abs().divRemTo(e, null, r),
            this.s < 0 && r.compareTo(o.ZERO) > 0 && e.subTo(r, r),
            r
          );
        }),
        (o.prototype.modPowInt = function (e, r) {
          var n;
          return (
            (n = e < 256 || r.isEven() ? new y(r) : new g(r)), this.exp(e, n)
          );
        }),
        (o.ZERO = _(0)),
        (o.ONE = _(1)),
        (B.prototype.convert = I),
        (B.prototype.revert = I),
        (B.prototype.mulTo = function (e, r, n) {
          e.multiplyTo(r, n);
        }),
        (B.prototype.sqrTo = function (e, r) {
          e.squareTo(r);
        }),
        (A.prototype.convert = function (e) {
          if (e.s < 0 || e.t > 2 * this.m.t) return e.mod(this.m);
          if (0 > e.compareTo(this.m)) return e;
          var r = c();
          return e.copyTo(r), this.reduce(r), r;
        }),
        (A.prototype.revert = function (e) {
          return e;
        }),
        (A.prototype.reduce = function (e) {
          for (
            e.drShiftTo(this.m.t - 1, this.r2),
              e.t > this.m.t + 1 && ((e.t = this.m.t + 1), e.clamp()),
              this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3),
              this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
            0 > e.compareTo(this.r2);

          )
            e.dAddOffset(1, this.m.t + 1);
          for (e.subTo(this.r2, e); e.compareTo(this.m) >= 0; )
            e.subTo(this.m, e);
        }),
        (A.prototype.mulTo = function (e, r, n) {
          e.multiplyTo(r, n), this.reduce(n);
        }),
        (A.prototype.sqrTo = function (e, r) {
          e.squareTo(r), this.reduce(r);
        });
      var b = [
          2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
          67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
          139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
          223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
          293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
          383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
          463, 467, 479, 487, 491, 499, 503, 509,
        ],
        N = 67108864 / b[b.length - 1];
      (o.prototype.chunkSize = function (e) {
        return Math.floor((Math.LN2 * this.DB) / Math.log(e));
      }),
        (o.prototype.toRadix = function (e) {
          if ((null == e && (e = 10), 0 == this.signum() || e < 2 || e > 36))
            return "0";
          var r = this.chunkSize(e),
            n = Math.pow(e, r),
            a = _(n),
            s = c(),
            o = c(),
            u = "";
          for (this.divRemTo(a, s, o); s.signum() > 0; )
            (u = (n + o.intValue()).toString(e).substr(1) + u),
              s.divRemTo(a, s, o);
          return o.intValue().toString(e) + u;
        }),
        (o.prototype.fromRadix = function (e, r) {
          this.fromInt(0), null == r && (r = 10);
          for (
            var n = this.chunkSize(r),
              a = Math.pow(r, n),
              s = !1,
              c = 0,
              u = 0,
              l = 0;
            l < e.length;
            ++l
          ) {
            var p = d(e, l);
            p < 0
              ? "-" == e.charAt(l) && 0 == this.signum() && (s = !0)
              : ((u = r * u + p),
                ++c >= n &&
                  (this.dMultiply(a), this.dAddOffset(u, 0), (c = 0), (u = 0)));
          }
          c > 0 && (this.dMultiply(Math.pow(r, c)), this.dAddOffset(u, 0)),
            s && o.ZERO.subTo(this, this);
        }),
        (o.prototype.fromNumber = function (e, r, n) {
          if ("number" == typeof r) {
            if (e < 2) this.fromInt(1);
            else
              for (
                this.fromNumber(e, n),
                  this.testBit(e - 1) ||
                    this.bitwiseTo(o.ONE.shiftLeft(e - 1), m, this),
                  this.isEven() && this.dAddOffset(1, 0);
                !this.isProbablePrime(r);

              )
                this.dAddOffset(2, 0),
                  this.bitLength() > e &&
                    this.subTo(o.ONE.shiftLeft(e - 1), this);
          } else {
            var a = [],
              s = 7 & e;
            (a.length = 1 + (e >> 3)),
              r.nextBytes(a),
              s > 0 ? (a[0] &= (1 << s) - 1) : (a[0] = 0),
              this.fromString(a, 256);
          }
        }),
        (o.prototype.bitwiseTo = function (e, r, n) {
          var a,
            s,
            o = Math.min(e.t, this.t);
          for (a = 0; a < o; ++a) n.data[a] = r(this.data[a], e.data[a]);
          if (e.t < this.t) {
            for (s = e.s & this.DM, a = o; a < this.t; ++a)
              n.data[a] = r(this.data[a], s);
            n.t = this.t;
          } else {
            for (s = this.s & this.DM, a = o; a < e.t; ++a)
              n.data[a] = r(s, e.data[a]);
            n.t = e.t;
          }
          (n.s = r(this.s, e.s)), n.clamp();
        }),
        (o.prototype.changeBit = function (e, r) {
          var n = o.ONE.shiftLeft(e);
          return this.bitwiseTo(n, r, n), n;
        }),
        (o.prototype.addTo = function (e, r) {
          for (var n = 0, a = 0, s = Math.min(e.t, this.t); n < s; )
            (a += this.data[n] + e.data[n]),
              (r.data[n++] = a & this.DM),
              (a >>= this.DB);
          if (e.t < this.t) {
            for (a += e.s; n < this.t; )
              (a += this.data[n]), (r.data[n++] = a & this.DM), (a >>= this.DB);
            a += this.s;
          } else {
            for (a += this.s; n < e.t; )
              (a += e.data[n]), (r.data[n++] = a & this.DM), (a >>= this.DB);
            a += e.s;
          }
          (r.s = a < 0 ? -1 : 0),
            a > 0 ? (r.data[n++] = a) : a < -1 && (r.data[n++] = this.DV + a),
            (r.t = n),
            r.clamp();
        }),
        (o.prototype.dMultiply = function (e) {
          (this.data[this.t] = this.am(0, e - 1, this, 0, 0, this.t)),
            ++this.t,
            this.clamp();
        }),
        (o.prototype.dAddOffset = function (e, r) {
          if (0 != e) {
            for (; this.t <= r; ) this.data[this.t++] = 0;
            for (this.data[r] += e; this.data[r] >= this.DV; )
              (this.data[r] -= this.DV),
                ++r >= this.t && (this.data[this.t++] = 0),
                ++this.data[r];
          }
        }),
        (o.prototype.multiplyLowerTo = function (e, r, n) {
          var a,
            s = Math.min(this.t + e.t, r);
          for (n.s = 0, n.t = s; s > 0; ) n.data[--s] = 0;
          for (a = n.t - this.t; s < a; ++s)
            n.data[s + this.t] = this.am(0, e.data[s], n, s, 0, this.t);
          for (a = Math.min(e.t, r); s < a; ++s)
            this.am(0, e.data[s], n, s, 0, r - s);
          n.clamp();
        }),
        (o.prototype.multiplyUpperTo = function (e, r, n) {
          --r;
          var a = (n.t = this.t + e.t - r);
          for (n.s = 0; --a >= 0; ) n.data[a] = 0;
          for (a = Math.max(r - this.t, 0); a < e.t; ++a)
            n.data[this.t + a - r] = this.am(
              r - a,
              e.data[a],
              n,
              0,
              0,
              this.t + a - r
            );
          n.clamp(), n.drShiftTo(1, n);
        }),
        (o.prototype.modInt = function (e) {
          if (e <= 0) return 0;
          var r = this.DV % e,
            n = this.s < 0 ? e - 1 : 0;
          if (this.t > 0) {
            if (0 == r) n = this.data[0] % e;
            else
              for (var a = this.t - 1; a >= 0; --a)
                n = (r * n + this.data[a]) % e;
          }
          return n;
        }),
        (o.prototype.millerRabin = function (e) {
          var r = this.subtract(o.ONE),
            n = r.getLowestSetBit();
          if (n <= 0) return !1;
          for (
            var a,
              s = r.shiftRight(n),
              c = {
                nextBytes: function (e) {
                  for (var r = 0; r < e.length; ++r)
                    e[r] = Math.floor(256 * Math.random());
                },
              },
              u = 0;
            u < e;
            ++u
          ) {
            do a = new o(this.bitLength(), c);
            while (0 >= a.compareTo(o.ONE) || a.compareTo(r) >= 0);
            var l = a.modPow(s, this);
            if (0 != l.compareTo(o.ONE) && 0 != l.compareTo(r)) {
              for (var p = 1; p++ < n && 0 != l.compareTo(r); )
                if (0 == (l = l.modPowInt(2, this)).compareTo(o.ONE)) return !1;
              if (0 != l.compareTo(r)) return !1;
            }
          }
          return !0;
        }),
        (o.prototype.clone = function () {
          var e = c();
          return this.copyTo(e), e;
        }),
        (o.prototype.intValue = function () {
          if (this.s < 0) {
            if (1 == this.t) return this.data[0] - this.DV;
            if (0 == this.t) return -1;
          } else {
            if (1 == this.t) return this.data[0];
            if (0 == this.t) return 0;
          }
          return (
            ((this.data[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) |
            this.data[0]
          );
        }),
        (o.prototype.byteValue = function () {
          return 0 == this.t ? this.s : (this.data[0] << 24) >> 24;
        }),
        (o.prototype.shortValue = function () {
          return 0 == this.t ? this.s : (this.data[0] << 16) >> 16;
        }),
        (o.prototype.signum = function () {
          return this.s < 0
            ? -1
            : this.t <= 0 || (1 == this.t && this.data[0] <= 0)
            ? 0
            : 1;
        }),
        (o.prototype.toByteArray = function () {
          var e = this.t,
            r = [];
          r[0] = this.s;
          var n,
            a = this.DB - ((e * this.DB) % 8),
            s = 0;
          if (e-- > 0)
            for (
              a < this.DB &&
              (n = this.data[e] >> a) != (this.s & this.DM) >> a &&
              (r[s++] = n | (this.s << (this.DB - a)));
              e >= 0;

            )
              a < 8
                ? ((n = (this.data[e] & ((1 << a) - 1)) << (8 - a)),
                  (n |= this.data[--e] >> (a += this.DB - 8)))
                : ((n = (this.data[e] >> (a -= 8)) & 255),
                  a <= 0 && ((a += this.DB), --e)),
                0 != (128 & n) && (n |= -256),
                0 == s && (128 & this.s) != (128 & n) && ++s,
                (s > 0 || n != this.s) && (r[s++] = n);
          return r;
        }),
        (o.prototype.equals = function (e) {
          return 0 == this.compareTo(e);
        }),
        (o.prototype.min = function (e) {
          return 0 > this.compareTo(e) ? this : e;
        }),
        (o.prototype.max = function (e) {
          return this.compareTo(e) > 0 ? this : e;
        }),
        (o.prototype.and = function (e) {
          var r = c();
          return this.bitwiseTo(e, v, r), r;
        }),
        (o.prototype.or = function (e) {
          var r = c();
          return this.bitwiseTo(e, m, r), r;
        }),
        (o.prototype.xor = function (e) {
          var r = c();
          return this.bitwiseTo(e, C, r), r;
        }),
        (o.prototype.andNot = function (e) {
          var r = c();
          return this.bitwiseTo(e, E, r), r;
        }),
        (o.prototype.not = function () {
          for (var e = c(), r = 0; r < this.t; ++r)
            e.data[r] = this.DM & ~this.data[r];
          return (e.t = this.t), (e.s = ~this.s), e;
        }),
        (o.prototype.shiftLeft = function (e) {
          var r = c();
          return e < 0 ? this.rShiftTo(-e, r) : this.lShiftTo(e, r), r;
        }),
        (o.prototype.shiftRight = function (e) {
          var r = c();
          return e < 0 ? this.lShiftTo(-e, r) : this.rShiftTo(e, r), r;
        }),
        (o.prototype.getLowestSetBit = function () {
          for (var e = 0; e < this.t; ++e)
            if (0 != this.data[e]) return e * this.DB + S(this.data[e]);
          return this.s < 0 ? this.t * this.DB : -1;
        }),
        (o.prototype.bitCount = function () {
          for (var e = 0, r = this.s & this.DM, n = 0; n < this.t; ++n)
            e += T(this.data[n] ^ r);
          return e;
        }),
        (o.prototype.testBit = function (e) {
          var r = Math.floor(e / this.DB);
          return r >= this.t
            ? 0 != this.s
            : 0 != (this.data[r] & (1 << e % this.DB));
        }),
        (o.prototype.setBit = function (e) {
          return this.changeBit(e, m);
        }),
        (o.prototype.clearBit = function (e) {
          return this.changeBit(e, E);
        }),
        (o.prototype.flipBit = function (e) {
          return this.changeBit(e, C);
        }),
        (o.prototype.add = function (e) {
          var r = c();
          return this.addTo(e, r), r;
        }),
        (o.prototype.subtract = function (e) {
          var r = c();
          return this.subTo(e, r), r;
        }),
        (o.prototype.multiply = function (e) {
          var r = c();
          return this.multiplyTo(e, r), r;
        }),
        (o.prototype.divide = function (e) {
          var r = c();
          return this.divRemTo(e, r, null), r;
        }),
        (o.prototype.remainder = function (e) {
          var r = c();
          return this.divRemTo(e, null, r), r;
        }),
        (o.prototype.divideAndRemainder = function (e) {
          var r = c(),
            n = c();
          return this.divRemTo(e, r, n), [r, n];
        }),
        (o.prototype.modPow = function (e, r) {
          var n,
            a,
            s = e.bitLength(),
            o = _(1);
          if (s <= 0) return o;
          (n = s < 18 ? 1 : s < 48 ? 3 : s < 144 ? 4 : s < 768 ? 5 : 6),
            (a = s < 8 ? new y(r) : r.isEven() ? new A(r) : new g(r));
          var u = [],
            l = 3,
            p = n - 1,
            f = (1 << n) - 1;
          if (((u[1] = a.convert(this)), n > 1)) {
            var h = c();
            for (a.sqrTo(u[1], h); l <= f; )
              (u[l] = c()), a.mulTo(h, u[l - 2], u[l]), (l += 2);
          }
          var d,
            v,
            m = e.t - 1,
            C = !0,
            E = c();
          for (s = $(e.data[m]) - 1; m >= 0; ) {
            for (
              s >= p
                ? (d = (e.data[m] >> (s - p)) & f)
                : ((d = (e.data[m] & ((1 << (s + 1)) - 1)) << (p - s)),
                  m > 0 && (d |= e.data[m - 1] >> (this.DB + s - p))),
                l = n;
              0 == (1 & d);

            )
              (d >>= 1), --l;
            if (((s -= l) < 0 && ((s += this.DB), --m), C))
              u[d].copyTo(o), (C = !1);
            else {
              for (; l > 1; ) a.sqrTo(o, E), a.sqrTo(E, o), (l -= 2);
              l > 0 ? a.sqrTo(o, E) : ((v = o), (o = E), (E = v)),
                a.mulTo(E, u[d], o);
            }
            for (; m >= 0 && 0 == (e.data[m] & (1 << s)); )
              a.sqrTo(o, E),
                (v = o),
                (o = E),
                (E = v),
                --s < 0 && ((s = this.DB - 1), --m);
          }
          return a.revert(o);
        }),
        (o.prototype.modInverse = function (e) {
          var r = e.isEven();
          if ((this.isEven() && r) || 0 == e.signum()) return o.ZERO;
          for (
            var n = e.clone(),
              a = this.clone(),
              s = _(1),
              c = _(0),
              u = _(0),
              l = _(1);
            0 != n.signum();

          ) {
            for (; n.isEven(); )
              n.rShiftTo(1, n),
                r
                  ? ((s.isEven() && c.isEven()) ||
                      (s.addTo(this, s), c.subTo(e, c)),
                    s.rShiftTo(1, s))
                  : c.isEven() || c.subTo(e, c),
                c.rShiftTo(1, c);
            for (; a.isEven(); )
              a.rShiftTo(1, a),
                r
                  ? ((u.isEven() && l.isEven()) ||
                      (u.addTo(this, u), l.subTo(e, l)),
                    u.rShiftTo(1, u))
                  : l.isEven() || l.subTo(e, l),
                l.rShiftTo(1, l);
            n.compareTo(a) >= 0
              ? (n.subTo(a, n), r && s.subTo(u, s), c.subTo(l, c))
              : (a.subTo(n, a), r && u.subTo(s, u), l.subTo(c, l));
          }
          return 0 != a.compareTo(o.ONE)
            ? o.ZERO
            : l.compareTo(e) >= 0
            ? l.subtract(e)
            : 0 > l.signum()
            ? (l.addTo(e, l), 0 > l.signum() ? l.add(e) : l)
            : l;
        }),
        (o.prototype.pow = function (e) {
          return this.exp(e, new B());
        }),
        (o.prototype.gcd = function (e) {
          var r = this.s < 0 ? this.negate() : this.clone(),
            n = e.s < 0 ? e.negate() : e.clone();
          if (0 > r.compareTo(n)) {
            var a = r;
            (r = n), (n = a);
          }
          var s = r.getLowestSetBit(),
            o = n.getLowestSetBit();
          if (o < 0) return r;
          for (
            s < o && (o = s), o > 0 && (r.rShiftTo(o, r), n.rShiftTo(o, n));
            r.signum() > 0;

          )
            (s = r.getLowestSetBit()) > 0 && r.rShiftTo(s, r),
              (s = n.getLowestSetBit()) > 0 && n.rShiftTo(s, n),
              r.compareTo(n) >= 0
                ? (r.subTo(n, r), r.rShiftTo(1, r))
                : (n.subTo(r, n), n.rShiftTo(1, n));
          return o > 0 && n.lShiftTo(o, n), n;
        }),
        (o.prototype.isProbablePrime = function (e) {
          var r,
            n = this.abs();
          if (1 == n.t && n.data[0] <= b[b.length - 1]) {
            for (r = 0; r < b.length; ++r) if (n.data[0] == b[r]) return !0;
            return !1;
          }
          if (n.isEven()) return !1;
          for (r = 1; r < b.length; ) {
            for (var a = b[r], s = r + 1; s < b.length && a < N; ) a *= b[s++];
            for (a = n.modInt(a); r < s; ) if (a % b[r++] == 0) return !1;
          }
          return n.millerRabin(e);
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(1),
        (e.exports = a.cipher = a.cipher || {}),
        (a.cipher.algorithms = a.cipher.algorithms || {}),
        (a.cipher.createCipher = function (e, r) {
          var n = e;
          if (
            ("string" == typeof n &&
              (n = a.cipher.getAlgorithm(n)) &&
              (n = n()),
            !n)
          )
            throw Error("Unsupported algorithm: " + e);
          return new a.cipher.BlockCipher({
            algorithm: n,
            key: r,
            decrypt: !1,
          });
        }),
        (a.cipher.createDecipher = function (e, r) {
          var n = e;
          if (
            ("string" == typeof n &&
              (n = a.cipher.getAlgorithm(n)) &&
              (n = n()),
            !n)
          )
            throw Error("Unsupported algorithm: " + e);
          return new a.cipher.BlockCipher({
            algorithm: n,
            key: r,
            decrypt: !0,
          });
        }),
        (a.cipher.registerAlgorithm = function (e, r) {
          (e = e.toUpperCase()), (a.cipher.algorithms[e] = r);
        }),
        (a.cipher.getAlgorithm = function (e) {
          return (e = e.toUpperCase()) in a.cipher.algorithms
            ? a.cipher.algorithms[e]
            : null;
        });
      var s = (a.cipher.BlockCipher = function (e) {
        (this.algorithm = e.algorithm),
          (this.mode = this.algorithm.mode),
          (this.blockSize = this.mode.blockSize),
          (this._finish = !1),
          (this._input = null),
          (this.output = null),
          (this._op = e.decrypt ? this.mode.decrypt : this.mode.encrypt),
          (this._decrypt = e.decrypt),
          this.algorithm.initialize(e);
      });
      (s.prototype.start = function (e) {
        e = e || {};
        var r = {};
        for (var n in e) r[n] = e[n];
        (r.decrypt = this._decrypt),
          (this._finish = !1),
          (this._input = a.util.createBuffer()),
          (this.output = e.output || a.util.createBuffer()),
          this.mode.start(r);
      }),
        (s.prototype.update = function (e) {
          for (
            e && this._input.putBuffer(e);
            !this._op.call(this.mode, this._input, this.output, this._finish) &&
            !this._finish;

          );
          this._input.compact();
        }),
        (s.prototype.finish = function (e) {
          e &&
            ("ECB" === this.mode.name || "CBC" === this.mode.name) &&
            ((this.mode.pad = function (r) {
              return e(this.blockSize, r, !1);
            }),
            (this.mode.unpad = function (r) {
              return e(this.blockSize, r, !0);
            }));
          var r = {};
          return (
            (r.decrypt = this._decrypt),
            (r.overflow = this._input.length() % this.blockSize),
            !(
              !this._decrypt &&
              this.mode.pad &&
              !this.mode.pad(this._input, r)
            ) &&
              ((this._finish = !0),
              this.update(),
              !(
                this._decrypt &&
                this.mode.unpad &&
                !this.mode.unpad(this.output, r)
              ) &&
                !(
                  this.mode.afterFinish &&
                  !this.mode.afterFinish(this.output, r)
                ))
          );
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(4), n(1);
      var s = (e.exports = a.md5 = a.md5 || {});
      (a.md.md5 = a.md.algorithms.md5 = s),
        (s.create = function () {
          p ||
            (function () {
              (o = "\x80"),
                (o += a.util.fillString("\0", 64)),
                (c = [
                  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6,
                  11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 5, 8, 11, 14,
                  1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3,
                  10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
                ]),
                (u = [
                  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5,
                  9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11,
                  16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
                  15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
                ]),
                (l = Array(64));
              for (var e = 0; e < 64; ++e)
                l[e] = Math.floor(4294967296 * Math.abs(Math.sin(e + 1)));
              p = !0;
            })();
          var e = null,
            r = a.util.createBuffer(),
            n = Array(16),
            s = {
              algorithm: "md5",
              blockLength: 64,
              digestLength: 16,
              messageLength: 0,
              fullMessageLength: null,
              messageLengthSize: 8,
              start: function () {
                (s.messageLength = 0),
                  (s.fullMessageLength = s.messageLength64 = []);
                for (var n = s.messageLengthSize / 4, o = 0; o < n; ++o)
                  s.fullMessageLength.push(0);
                return (
                  (r = a.util.createBuffer()),
                  (e = {
                    h0: 1732584193,
                    h1: 4023233417,
                    h2: 2562383102,
                    h3: 271733878,
                  }),
                  s
                );
              },
            };
          return (
            s.start(),
            (s.update = function (o, c) {
              "utf8" === c && (o = a.util.encodeUtf8(o));
              var u = o.length;
              (s.messageLength += u), (u = [(u / 4294967296) >>> 0, u >>> 0]);
              for (var l = s.fullMessageLength.length - 1; l >= 0; --l)
                (s.fullMessageLength[l] += u[1]),
                  (u[1] = u[0] + ((s.fullMessageLength[l] / 4294967296) >>> 0)),
                  (s.fullMessageLength[l] = s.fullMessageLength[l] >>> 0),
                  (u[0] = (u[1] / 4294967296) >>> 0);
              return (
                r.putBytes(o),
                f(e, n, r),
                (r.read > 2048 || 0 === r.length()) && r.compact(),
                s
              );
            }),
            (s.digest = function () {
              var c = a.util.createBuffer();
              c.putBytes(r.bytes());
              var u =
                (s.fullMessageLength[s.fullMessageLength.length - 1] +
                  s.messageLengthSize) &
                (s.blockLength - 1);
              c.putBytes(o.substr(0, s.blockLength - u));
              for (
                var l, p = 0, h = s.fullMessageLength.length - 1;
                h >= 0;
                --h
              )
                (p = ((l = 8 * s.fullMessageLength[h] + p) / 4294967296) >>> 0),
                  c.putInt32Le(l >>> 0);
              var d = { h0: e.h0, h1: e.h1, h2: e.h2, h3: e.h3 };
              f(d, n, c);
              var _ = a.util.createBuffer();
              return (
                _.putInt32Le(d.h0),
                _.putInt32Le(d.h1),
                _.putInt32Le(d.h2),
                _.putInt32Le(d.h3),
                _
              );
            }),
            s
          );
        });
      var o = null,
        c = null,
        u = null,
        l = null,
        p = !1;
      function f(e, r, n) {
        for (var a, s, o, p, f, h, d, _ = n.length(); _ >= 64; ) {
          for (s = e.h0, o = e.h1, p = e.h2, f = e.h3, d = 0; d < 16; ++d)
            (r[d] = n.getInt32Le()),
              (a = s + (f ^ (o & (p ^ f))) + l[d] + r[d]),
              (s = f),
              (f = p),
              (p = o),
              (o += (a << (h = u[d])) | (a >>> (32 - h)));
          for (; d < 32; ++d)
            (a = s + (p ^ (f & (o ^ p))) + l[d] + r[c[d]]),
              (s = f),
              (f = p),
              (p = o),
              (o += (a << (h = u[d])) | (a >>> (32 - h)));
          for (; d < 48; ++d)
            (a = s + (o ^ p ^ f) + l[d] + r[c[d]]),
              (s = f),
              (f = p),
              (p = o),
              (o += (a << (h = u[d])) | (a >>> (32 - h)));
          for (; d < 64; ++d)
            (a = s + (p ^ (o | ~f)) + l[d] + r[c[d]]),
              (s = f),
              (f = p),
              (p = o),
              (o += (a << (h = u[d])) | (a >>> (32 - h)));
          (e.h0 = (e.h0 + s) | 0),
            (e.h1 = (e.h1 + o) | 0),
            (e.h2 = (e.h2 + p) | 0),
            (e.h3 = (e.h3 + f) | 0),
            (_ -= 64);
        }
      }
    },
    function (e, r, n) {
      var a = n(0);
      n(8), n(4), n(1);
      var s,
        o = (a.pkcs5 = a.pkcs5 || {});
      a.util.isNodejs && !a.options.usePureJavaScript && (s = n(16)),
        (e.exports =
          a.pbkdf2 =
          o.pbkdf2 =
            function (e, r, n, o, c, u) {
              if (
                ("function" == typeof c && ((u = c), (c = null)),
                a.util.isNodejs &&
                  !a.options.usePureJavaScript &&
                  s.pbkdf2 &&
                  (null === c || "object" != typeof c) &&
                  (s.pbkdf2Sync.length > 4 || !c || "sha1" === c))
              )
                return (
                  "string" != typeof c && (c = "sha1"),
                  (e = Buffer.from(e, "binary")),
                  (r = Buffer.from(r, "binary")),
                  u
                    ? 4 === s.pbkdf2Sync.length
                      ? s.pbkdf2(e, r, n, o, function (e, r) {
                          if (e) return u(e);
                          u(null, r.toString("binary"));
                        })
                      : s.pbkdf2(e, r, n, o, c, function (e, r) {
                          if (e) return u(e);
                          u(null, r.toString("binary"));
                        })
                    : 4 === s.pbkdf2Sync.length
                    ? s.pbkdf2Sync(e, r, n, o).toString("binary")
                    : s.pbkdf2Sync(e, r, n, o, c).toString("binary")
                );
              if ((null == c && (c = "sha1"), "string" == typeof c)) {
                if (!(c in a.md.algorithms))
                  throw Error("Unknown hash algorithm: " + c);
                c = a.md[c].create();
              }
              var l = c.digestLength;
              if (o > 4294967295 * l) {
                var p = Error("Derived key is too long.");
                if (u) return u(p);
                throw p;
              }
              var f = Math.ceil(o / l),
                h = o - (f - 1) * l,
                d = a.hmac.create();
              d.start(c, e);
              var _,
                $,
                y,
                g = "";
              if (!u) {
                for (var v = 1; v <= f; ++v) {
                  d.start(null, null),
                    d.update(r),
                    d.update(a.util.int32ToBytes(v)),
                    (_ = y = d.digest().getBytes());
                  for (var m = 2; m <= n; ++m)
                    d.start(null, null),
                      d.update(y),
                      ($ = d.digest().getBytes()),
                      (_ = a.util.xorBytes(_, $, l)),
                      (y = $);
                  g += v < f ? _ : _.substr(0, h);
                }
                return g;
              }
              (v = 1),
                (function e() {
                  if (v > f) return u(null, g);
                  d.start(null, null),
                    d.update(r),
                    d.update(a.util.int32ToBytes(v)),
                    (_ = y = d.digest().getBytes()),
                    (m = 2),
                    (function r() {
                      if (m <= n)
                        return (
                          d.start(null, null),
                          d.update(y),
                          ($ = d.digest().getBytes()),
                          (_ = a.util.xorBytes(_, $, l)),
                          (y = $),
                          ++m,
                          a.util.setImmediate(r)
                        );
                      (g += v < f ? _ : _.substr(0, h)), ++v, e();
                    })();
                })();
            });
    },
    function (e, r) {},
    function (e, r, n) {
      var a = n(0);
      n(5), n(3), n(10), n(4), n(37), n(6), n(7), n(18), n(11), n(1);
      var s = a.asn1,
        o = (e.exports = a.pki = a.pki || {}),
        c = o.oids,
        u = {};
      (u.CN = c.commonName),
        (u.commonName = "CN"),
        (u.C = c.countryName),
        (u.countryName = "C"),
        (u.L = c.localityName),
        (u.localityName = "L"),
        (u.ST = c.stateOrProvinceName),
        (u.stateOrProvinceName = "ST"),
        (u.O = c.organizationName),
        (u.organizationName = "O"),
        (u.OU = c.organizationalUnitName),
        (u.organizationalUnitName = "OU"),
        (u.E = c.emailAddress),
        (u.emailAddress = "E");
      var l = a.pki.rsa.publicKeyValidator,
        p = {
          name: "Certificate",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "Certificate.TBSCertificate",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              captureAsn1: "tbsCertificate",
              value: [
                {
                  name: "Certificate.TBSCertificate.version",
                  tagClass: s.Class.CONTEXT_SPECIFIC,
                  type: 0,
                  constructed: !0,
                  optional: !0,
                  value: [
                    {
                      name: "Certificate.TBSCertificate.version.integer",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.INTEGER,
                      constructed: !1,
                      capture: "certVersion",
                    },
                  ],
                },
                {
                  name: "Certificate.TBSCertificate.serialNumber",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.INTEGER,
                  constructed: !1,
                  capture: "certSerialNumber",
                },
                {
                  name: "Certificate.TBSCertificate.signature",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.SEQUENCE,
                  constructed: !0,
                  value: [
                    {
                      name: "Certificate.TBSCertificate.signature.algorithm",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.OID,
                      constructed: !1,
                      capture: "certinfoSignatureOid",
                    },
                    {
                      name: "Certificate.TBSCertificate.signature.parameters",
                      tagClass: s.Class.UNIVERSAL,
                      optional: !0,
                      captureAsn1: "certinfoSignatureParams",
                    },
                  ],
                },
                {
                  name: "Certificate.TBSCertificate.issuer",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.SEQUENCE,
                  constructed: !0,
                  captureAsn1: "certIssuer",
                },
                {
                  name: "Certificate.TBSCertificate.validity",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.SEQUENCE,
                  constructed: !0,
                  value: [
                    {
                      name: "Certificate.TBSCertificate.validity.notBefore (utc)",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.UTCTIME,
                      constructed: !1,
                      optional: !0,
                      capture: "certValidity1UTCTime",
                    },
                    {
                      name: "Certificate.TBSCertificate.validity.notBefore (generalized)",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.GENERALIZEDTIME,
                      constructed: !1,
                      optional: !0,
                      capture: "certValidity2GeneralizedTime",
                    },
                    {
                      name: "Certificate.TBSCertificate.validity.notAfter (utc)",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.UTCTIME,
                      constructed: !1,
                      optional: !0,
                      capture: "certValidity3UTCTime",
                    },
                    {
                      name: "Certificate.TBSCertificate.validity.notAfter (generalized)",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.GENERALIZEDTIME,
                      constructed: !1,
                      optional: !0,
                      capture: "certValidity4GeneralizedTime",
                    },
                  ],
                },
                {
                  name: "Certificate.TBSCertificate.subject",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.SEQUENCE,
                  constructed: !0,
                  captureAsn1: "certSubject",
                },
                l,
                {
                  name: "Certificate.TBSCertificate.issuerUniqueID",
                  tagClass: s.Class.CONTEXT_SPECIFIC,
                  type: 1,
                  constructed: !0,
                  optional: !0,
                  value: [
                    {
                      name: "Certificate.TBSCertificate.issuerUniqueID.id",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.BITSTRING,
                      constructed: !1,
                      captureBitStringValue: "certIssuerUniqueId",
                    },
                  ],
                },
                {
                  name: "Certificate.TBSCertificate.subjectUniqueID",
                  tagClass: s.Class.CONTEXT_SPECIFIC,
                  type: 2,
                  constructed: !0,
                  optional: !0,
                  value: [
                    {
                      name: "Certificate.TBSCertificate.subjectUniqueID.id",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.BITSTRING,
                      constructed: !1,
                      captureBitStringValue: "certSubjectUniqueId",
                    },
                  ],
                },
                {
                  name: "Certificate.TBSCertificate.extensions",
                  tagClass: s.Class.CONTEXT_SPECIFIC,
                  type: 3,
                  constructed: !0,
                  captureAsn1: "certExtensions",
                  optional: !0,
                },
              ],
            },
            {
              name: "Certificate.signatureAlgorithm",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "Certificate.signatureAlgorithm.algorithm",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.OID,
                  constructed: !1,
                  capture: "certSignatureOid",
                },
                {
                  name: "Certificate.TBSCertificate.signature.parameters",
                  tagClass: s.Class.UNIVERSAL,
                  optional: !0,
                  captureAsn1: "certSignatureParams",
                },
              ],
            },
            {
              name: "Certificate.signatureValue",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.BITSTRING,
              constructed: !1,
              captureBitStringValue: "certSignature",
            },
          ],
        },
        f = {
          name: "rsapss",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "rsapss.hashAlgorithm",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              type: 0,
              constructed: !0,
              value: [
                {
                  name: "rsapss.hashAlgorithm.AlgorithmIdentifier",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Class.SEQUENCE,
                  constructed: !0,
                  optional: !0,
                  value: [
                    {
                      name: "rsapss.hashAlgorithm.AlgorithmIdentifier.algorithm",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.OID,
                      constructed: !1,
                      capture: "hashOid",
                    },
                  ],
                },
              ],
            },
            {
              name: "rsapss.maskGenAlgorithm",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              type: 1,
              constructed: !0,
              value: [
                {
                  name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Class.SEQUENCE,
                  constructed: !0,
                  optional: !0,
                  value: [
                    {
                      name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier.algorithm",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.OID,
                      constructed: !1,
                      capture: "maskGenOid",
                    },
                    {
                      name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier.params",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.SEQUENCE,
                      constructed: !0,
                      value: [
                        {
                          name: "rsapss.maskGenAlgorithm.AlgorithmIdentifier.params.algorithm",
                          tagClass: s.Class.UNIVERSAL,
                          type: s.Type.OID,
                          constructed: !1,
                          capture: "maskGenHashOid",
                        },
                      ],
                    },
                  ],
                },
              ],
            },
            {
              name: "rsapss.saltLength",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              type: 2,
              optional: !0,
              value: [
                {
                  name: "rsapss.saltLength.saltLength",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Class.INTEGER,
                  constructed: !1,
                  capture: "saltLength",
                },
              ],
            },
            {
              name: "rsapss.trailerField",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              type: 3,
              optional: !0,
              value: [
                {
                  name: "rsapss.trailer.trailer",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Class.INTEGER,
                  constructed: !1,
                  capture: "trailer",
                },
              ],
            },
          ],
        },
        h = {
          name: "CertificationRequestInfo",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          captureAsn1: "certificationRequestInfo",
          value: [
            {
              name: "CertificationRequestInfo.integer",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.INTEGER,
              constructed: !1,
              capture: "certificationRequestInfoVersion",
            },
            {
              name: "CertificationRequestInfo.subject",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              captureAsn1: "certificationRequestInfoSubject",
            },
            l,
            {
              name: "CertificationRequestInfo.attributes",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              type: 0,
              constructed: !0,
              optional: !0,
              capture: "certificationRequestInfoAttributes",
              value: [
                {
                  name: "CertificationRequestInfo.attributes",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.SEQUENCE,
                  constructed: !0,
                  value: [
                    {
                      name: "CertificationRequestInfo.attributes.type",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.OID,
                      constructed: !1,
                    },
                    {
                      name: "CertificationRequestInfo.attributes.value",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.SET,
                      constructed: !0,
                    },
                  ],
                },
              ],
            },
          ],
        },
        d = {
          name: "CertificationRequest",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          captureAsn1: "csr",
          value: [
            h,
            {
              name: "CertificationRequest.signatureAlgorithm",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "CertificationRequest.signatureAlgorithm.algorithm",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.OID,
                  constructed: !1,
                  capture: "csrSignatureOid",
                },
                {
                  name: "CertificationRequest.signatureAlgorithm.parameters",
                  tagClass: s.Class.UNIVERSAL,
                  optional: !0,
                  captureAsn1: "csrSignatureParams",
                },
              ],
            },
            {
              name: "CertificationRequest.signature",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.BITSTRING,
              constructed: !1,
              captureBitStringValue: "csrSignature",
            },
          ],
        };
      function _(e, r) {
        "string" == typeof r && (r = { shortName: r });
        for (var n, a = null, s = 0; null === a && s < e.attributes.length; ++s)
          (n = e.attributes[s]),
            ((r.type && r.type === n.type) ||
              (r.name && r.name === n.name) ||
              (r.shortName && r.shortName === n.shortName)) &&
              (a = n);
        return a;
      }
      (o.RDNAttributesAsArray = function (e, r) {
        for (var n, a, o, l = [], p = 0; p < e.value.length; ++p) {
          n = e.value[p];
          for (var f = 0; f < n.value.length; ++f)
            (o = {}),
              (a = n.value[f]),
              (o.type = s.derToOid(a.value[0].value)),
              (o.value = a.value[1].value),
              (o.valueTagClass = a.value[1].type),
              o.type in c &&
                ((o.name = c[o.type]),
                o.name in u && (o.shortName = u[o.name])),
              r && (r.update(o.type), r.update(o.value)),
              l.push(o);
        }
        return l;
      }),
        (o.CRIAttributesAsArray = function (e) {
          for (var r = [], n = 0; n < e.length; ++n)
            for (
              var a = e[n],
                l = s.derToOid(a.value[0].value),
                p = a.value[1].value,
                f = 0;
              f < p.length;
              ++f
            ) {
              var h = {};
              if (
                ((h.type = l),
                (h.value = p[f].value),
                (h.valueTagClass = p[f].type),
                h.type in c &&
                  ((h.name = c[h.type]),
                  h.name in u && (h.shortName = u[h.name])),
                h.type === c.extensionRequest)
              ) {
                h.extensions = [];
                for (var d = 0; d < h.value.length; ++d)
                  h.extensions.push(o.certificateExtensionFromAsn1(h.value[d]));
              }
              r.push(h);
            }
          return r;
        });
      var $ = function (e, r, n) {
          var a = {};
          if (e !== c["RSASSA-PSS"]) return a;
          n &&
            (a = {
              hash: { algorithmOid: c.sha1 },
              mgf: { algorithmOid: c.mgf1, hash: { algorithmOid: c.sha1 } },
              saltLength: 20,
            });
          var o = {},
            u = [];
          if (!s.validate(r, f, o, u)) {
            var l = Error("Cannot read RSASSA-PSS parameter block.");
            throw ((l.errors = u), l);
          }
          return (
            void 0 !== o.hashOid &&
              ((a.hash = a.hash || {}),
              (a.hash.algorithmOid = s.derToOid(o.hashOid))),
            void 0 !== o.maskGenOid &&
              ((a.mgf = a.mgf || {}),
              (a.mgf.algorithmOid = s.derToOid(o.maskGenOid)),
              (a.mgf.hash = a.mgf.hash || {}),
              (a.mgf.hash.algorithmOid = s.derToOid(o.maskGenHashOid))),
            void 0 !== o.saltLength &&
              (a.saltLength = o.saltLength.charCodeAt(0)),
            a
          );
        },
        y = function (e) {
          switch (c[e.signatureOid]) {
            case "sha1WithRSAEncryption":
            case "sha1WithRSASignature":
              return a.md.sha1.create();
            case "md5WithRSAEncryption":
              return a.md.md5.create();
            case "sha256WithRSAEncryption":
            case "RSASSA-PSS":
              return a.md.sha256.create();
            case "sha384WithRSAEncryption":
              return a.md.sha384.create();
            case "sha512WithRSAEncryption":
              return a.md.sha512.create();
            default:
              var r = Error(
                "Could not compute " +
                  e.type +
                  " digest. Unknown signature OID."
              );
              throw ((r.signatureOid = e.signatureOid), r);
          }
        },
        g = function (e) {
          var r,
            n,
            s,
            o,
            u = e.certificate;
          switch (u.signatureOid) {
            case c.sha1WithRSAEncryption:
            case c.sha1WithRSASignature:
              break;
            case c["RSASSA-PSS"]:
              if (
                void 0 ===
                  (r = c[u.signatureParameters.mgf.hash.algorithmOid]) ||
                void 0 === a.md[r]
              )
                throw (
                  (((s = Error("Unsupported MGF hash function.")).oid =
                    u.signatureParameters.mgf.hash.algorithmOid),
                  (s.name = r),
                  s)
                );
              if (
                void 0 === (n = c[u.signatureParameters.mgf.algorithmOid]) ||
                void 0 === a.mgf[n]
              )
                throw (
                  (((s = Error("Unsupported MGF function.")).oid =
                    u.signatureParameters.mgf.algorithmOid),
                  (s.name = n),
                  s)
                );
              if (
                ((n = a.mgf[n].create(a.md[r].create())),
                void 0 === (r = c[u.signatureParameters.hash.algorithmOid]) ||
                  void 0 === a.md[r])
              )
                throw (
                  (((s = Error("Unsupported RSASSA-PSS hash function.")).oid =
                    u.signatureParameters.hash.algorithmOid),
                  (s.name = r),
                  s)
                );
              o = a.pss.create(
                a.md[r].create(),
                n,
                u.signatureParameters.saltLength
              );
          }
          return u.publicKey.verify(e.md.digest().getBytes(), e.signature, o);
        };
      function v(e) {
        for (
          var r,
            n,
            o = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, []),
            c = e.attributes,
            u = 0;
          u < c.length;
          ++u
        ) {
          var l = (r = c[u]).value,
            p = s.Type.PRINTABLESTRING;
          "valueTagClass" in r &&
            (p = r.valueTagClass) === s.Type.UTF8 &&
            (l = a.util.encodeUtf8(l)),
            (n = s.create(s.Class.UNIVERSAL, s.Type.SET, !0, [
              s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OID,
                  !1,
                  s.oidToDer(r.type).getBytes()
                ),
                s.create(s.Class.UNIVERSAL, p, !1, l),
              ]),
            ])),
            o.value.push(n);
        }
        return o;
      }
      function m(e) {
        for (var r, n = 0; n < e.length; ++n) {
          if (
            (void 0 === (r = e[n]).name &&
              (r.type && r.type in o.oids
                ? (r.name = o.oids[r.type])
                : r.shortName &&
                  r.shortName in u &&
                  (r.name = o.oids[u[r.shortName]])),
            void 0 === r.type)
          ) {
            if (!r.name || !(r.name in o.oids))
              throw (
                (((a = Error("Attribute type not specified.")).attribute = r),
                a)
              );
            r.type = o.oids[r.name];
          }
          if (
            (void 0 === r.shortName &&
              r.name &&
              r.name in u &&
              (r.shortName = u[r.name]),
            r.type === c.extensionRequest &&
              ((r.valueConstructed = !0),
              (r.valueTagClass = s.Type.SEQUENCE),
              !r.value && r.extensions))
          ) {
            r.value = [];
            for (var a, l = 0; l < r.extensions.length; ++l)
              r.value.push(o.certificateExtensionToAsn1(C(r.extensions[l])));
          }
          if (void 0 === r.value)
            throw (
              (((a = Error("Attribute value not specified.")).attribute = r), a)
            );
        }
      }
      function C(e, r) {
        if (
          ((r = r || {}),
          void 0 === e.name &&
            e.id &&
            e.id in o.oids &&
            (e.name = o.oids[e.id]),
          void 0 === e.id)
        ) {
          if (!e.name || !(e.name in o.oids))
            throw (
              (((n = Error("Extension ID not specified.")).extension = e), n)
            );
          e.id = o.oids[e.name];
        }
        if (void 0 !== e.value) return e;
        if ("keyUsage" === e.name) {
          var n,
            u = 0,
            l = 0,
            p = 0;
          e.digitalSignature && ((l |= 128), (u = 7)),
            e.nonRepudiation && ((l |= 64), (u = 6)),
            e.keyEncipherment && ((l |= 32), (u = 5)),
            e.dataEncipherment && ((l |= 16), (u = 4)),
            e.keyAgreement && ((l |= 8), (u = 3)),
            e.keyCertSign && ((l |= 4), (u = 2)),
            e.cRLSign && ((l |= 2), (u = 1)),
            e.encipherOnly && ((l |= 1), (u = 0)),
            e.decipherOnly && ((p |= 128), (u = 7));
          var f = String.fromCharCode(u);
          0 !== p
            ? (f += String.fromCharCode(l) + String.fromCharCode(p))
            : 0 !== l && (f += String.fromCharCode(l)),
            (e.value = s.create(s.Class.UNIVERSAL, s.Type.BITSTRING, !1, f));
        } else if ("basicConstraints" === e.name)
          (e.value = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [])),
            e.cA &&
              e.value.value.push(
                s.create(s.Class.UNIVERSAL, s.Type.BOOLEAN, !1, "\xff")
              ),
            "pathLenConstraint" in e &&
              e.value.value.push(
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.INTEGER,
                  !1,
                  s.integerToDer(e.pathLenConstraint).getBytes()
                )
              );
        else if ("extKeyUsage" === e.name) {
          e.value = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, []);
          var h = e.value.value;
          for (var d in e)
            !0 === e[d] &&
              (d in c
                ? h.push(
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.OID,
                      !1,
                      s.oidToDer(c[d]).getBytes()
                    )
                  )
                : -1 !== d.indexOf(".") &&
                  h.push(
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.OID,
                      !1,
                      s.oidToDer(d).getBytes()
                    )
                  ));
        } else if ("nsCertType" === e.name)
          (u = 0),
            (l = 0),
            e.client && ((l |= 128), (u = 7)),
            e.server && ((l |= 64), (u = 6)),
            e.email && ((l |= 32), (u = 5)),
            e.objsign && ((l |= 16), (u = 4)),
            e.reserved && ((l |= 8), (u = 3)),
            e.sslCA && ((l |= 4), (u = 2)),
            e.emailCA && ((l |= 2), (u = 1)),
            e.objCA && ((l |= 1), (u = 0)),
            (f = String.fromCharCode(u)),
            0 !== l && (f += String.fromCharCode(l)),
            (e.value = s.create(s.Class.UNIVERSAL, s.Type.BITSTRING, !1, f));
        else if ("subjectAltName" === e.name || "issuerAltName" === e.name) {
          e.value = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, []);
          for (var _ = 0; _ < e.altNames.length; ++_) {
            if (((f = (C = e.altNames[_]).value), 7 === C.type && C.ip)) {
              if (null === (f = a.util.bytesFromIP(C.ip)))
                throw (
                  (((n = Error(
                    'Extension "ip" value is not a valid IPv4 or IPv6 address.'
                  )).extension = e),
                  n)
                );
            } else
              8 === C.type &&
                (f = C.oid ? s.oidToDer(s.oidToDer(C.oid)) : s.oidToDer(f));
            e.value.value.push(
              s.create(s.Class.CONTEXT_SPECIFIC, C.type, !1, f)
            );
          }
        } else if ("nsComment" === e.name && r.cert) {
          if (
            !/^[\x00-\x7F]*$/.test(e.comment) ||
            e.comment.length < 1 ||
            e.comment.length > 128
          )
            throw Error('Invalid "nsComment" content.');
          e.value = s.create(
            s.Class.UNIVERSAL,
            s.Type.IA5STRING,
            !1,
            e.comment
          );
        } else if ("subjectKeyIdentifier" === e.name && r.cert) {
          var $ = r.cert.generateSubjectKeyIdentifier();
          (e.subjectKeyIdentifier = $.toHex()),
            (e.value = s.create(
              s.Class.UNIVERSAL,
              s.Type.OCTETSTRING,
              !1,
              $.getBytes()
            ));
        } else if ("authorityKeyIdentifier" === e.name && r.cert) {
          if (
            ((e.value = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [])),
            (h = e.value.value),
            e.keyIdentifier)
          ) {
            var y =
              !0 === e.keyIdentifier
                ? r.cert.generateSubjectKeyIdentifier().getBytes()
                : e.keyIdentifier;
            h.push(s.create(s.Class.CONTEXT_SPECIFIC, 0, !1, y));
          }
          if (e.authorityCertIssuer) {
            var g = [
              s.create(s.Class.CONTEXT_SPECIFIC, 4, !0, [
                v(
                  !0 === e.authorityCertIssuer
                    ? r.cert.issuer
                    : e.authorityCertIssuer
                ),
              ]),
            ];
            h.push(s.create(s.Class.CONTEXT_SPECIFIC, 1, !0, g));
          }
          if (e.serialNumber) {
            var m = a.util.hexToBytes(
              !0 === e.serialNumber ? r.cert.serialNumber : e.serialNumber
            );
            h.push(s.create(s.Class.CONTEXT_SPECIFIC, 2, !1, m));
          }
        } else if ("cRLDistributionPoints" === e.name) {
          (e.value = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [])),
            (h = e.value.value);
          var C,
            E = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, []),
            S = s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, []);
          for (_ = 0; _ < e.altNames.length; ++_) {
            if (((f = (C = e.altNames[_]).value), 7 === C.type && C.ip)) {
              if (null === (f = a.util.bytesFromIP(C.ip)))
                throw (
                  (((n = Error(
                    'Extension "ip" value is not a valid IPv4 or IPv6 address.'
                  )).extension = e),
                  n)
                );
            } else
              8 === C.type &&
                (f = C.oid ? s.oidToDer(s.oidToDer(C.oid)) : s.oidToDer(f));
            S.value.push(s.create(s.Class.CONTEXT_SPECIFIC, C.type, !1, f));
          }
          E.value.push(s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [S])),
            h.push(E);
        }
        if (void 0 === e.value)
          throw (
            (((n = Error("Extension value not specified.")).extension = e), n)
          );
        return e;
      }
      function E(e, r) {
        if (e === c["RSASSA-PSS"]) {
          var n = [];
          return (
            void 0 !== r.hash.algorithmOid &&
              n.push(
                s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                  s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.OID,
                      !1,
                      s.oidToDer(r.hash.algorithmOid).getBytes()
                    ),
                    s.create(s.Class.UNIVERSAL, s.Type.NULL, !1, ""),
                  ]),
                ])
              ),
            void 0 !== r.mgf.algorithmOid &&
              n.push(
                s.create(s.Class.CONTEXT_SPECIFIC, 1, !0, [
                  s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.OID,
                      !1,
                      s.oidToDer(r.mgf.algorithmOid).getBytes()
                    ),
                    s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                      s.create(
                        s.Class.UNIVERSAL,
                        s.Type.OID,
                        !1,
                        s.oidToDer(r.mgf.hash.algorithmOid).getBytes()
                      ),
                      s.create(s.Class.UNIVERSAL, s.Type.NULL, !1, ""),
                    ]),
                  ]),
                ])
              ),
            void 0 !== r.saltLength &&
              n.push(
                s.create(s.Class.CONTEXT_SPECIFIC, 2, !0, [
                  s.create(
                    s.Class.UNIVERSAL,
                    s.Type.INTEGER,
                    !1,
                    s.integerToDer(r.saltLength).getBytes()
                  ),
                ])
              ),
            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, n)
          );
        }
        return s.create(s.Class.UNIVERSAL, s.Type.NULL, !1, "");
      }
      (o.certificateFromPem = function (e, r, n) {
        var c = a.pem.decode(e)[0];
        if (
          "CERTIFICATE" !== c.type &&
          "X509 CERTIFICATE" !== c.type &&
          "TRUSTED CERTIFICATE" !== c.type
        ) {
          var u = Error(
            'Could not convert certificate from PEM; PEM header type is not "CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE".'
          );
          throw ((u.headerType = c.type), u);
        }
        if (c.procType && "ENCRYPTED" === c.procType.type)
          throw Error(
            "Could not convert certificate from PEM; PEM is encrypted."
          );
        var l = s.fromDer(c.body, n);
        return o.certificateFromAsn1(l, r);
      }),
        (o.certificateToPem = function (e, r) {
          var n = {
            type: "CERTIFICATE",
            body: s.toDer(o.certificateToAsn1(e)).getBytes(),
          };
          return a.pem.encode(n, { maxline: r });
        }),
        (o.publicKeyFromPem = function (e) {
          var r = a.pem.decode(e)[0];
          if ("PUBLIC KEY" !== r.type && "RSA PUBLIC KEY" !== r.type) {
            var n = Error(
              'Could not convert public key from PEM; PEM header type is not "PUBLIC KEY" or "RSA PUBLIC KEY".'
            );
            throw ((n.headerType = r.type), n);
          }
          if (r.procType && "ENCRYPTED" === r.procType.type)
            throw Error(
              "Could not convert public key from PEM; PEM is encrypted."
            );
          var c = s.fromDer(r.body);
          return o.publicKeyFromAsn1(c);
        }),
        (o.publicKeyToPem = function (e, r) {
          var n = {
            type: "PUBLIC KEY",
            body: s.toDer(o.publicKeyToAsn1(e)).getBytes(),
          };
          return a.pem.encode(n, { maxline: r });
        }),
        (o.publicKeyToRSAPublicKeyPem = function (e, r) {
          var n = {
            type: "RSA PUBLIC KEY",
            body: s.toDer(o.publicKeyToRSAPublicKey(e)).getBytes(),
          };
          return a.pem.encode(n, { maxline: r });
        }),
        (o.getPublicKeyFingerprint = function (e, r) {
          var n,
            c = (r = r || {}).md || a.md.sha1.create();
          switch (r.type || "RSAPublicKey") {
            case "RSAPublicKey":
              n = s.toDer(o.publicKeyToRSAPublicKey(e)).getBytes();
              break;
            case "SubjectPublicKeyInfo":
              n = s.toDer(o.publicKeyToAsn1(e)).getBytes();
              break;
            default:
              throw Error('Unknown fingerprint type "' + r.type + '".');
          }
          c.start(), c.update(n);
          var u = c.digest();
          if ("hex" === r.encoding) {
            var l = u.toHex();
            return r.delimiter ? l.match(/.{2}/g).join(r.delimiter) : l;
          }
          if ("binary" === r.encoding) return u.getBytes();
          if (r.encoding) throw Error('Unknown encoding "' + r.encoding + '".');
          return u;
        }),
        (o.certificationRequestFromPem = function (e, r, n) {
          var c = a.pem.decode(e)[0];
          if ("CERTIFICATE REQUEST" !== c.type) {
            var u = Error(
              'Could not convert certification request from PEM; PEM header type is not "CERTIFICATE REQUEST".'
            );
            throw ((u.headerType = c.type), u);
          }
          if (c.procType && "ENCRYPTED" === c.procType.type)
            throw Error(
              "Could not convert certification request from PEM; PEM is encrypted."
            );
          var l = s.fromDer(c.body, n);
          return o.certificationRequestFromAsn1(l, r);
        }),
        (o.certificationRequestToPem = function (e, r) {
          var n = {
            type: "CERTIFICATE REQUEST",
            body: s.toDer(o.certificationRequestToAsn1(e)).getBytes(),
          };
          return a.pem.encode(n, { maxline: r });
        }),
        (o.createCertificate = function () {
          var e = {
            version: 2,
            serialNumber: "00",
            signatureOid: null,
            signature: null,
            siginfo: {},
          };
          return (
            (e.siginfo.algorithmOid = null),
            (e.validity = {}),
            (e.validity.notBefore = new Date()),
            (e.validity.notAfter = new Date()),
            (e.issuer = {}),
            (e.issuer.getField = function (r) {
              return _(e.issuer, r);
            }),
            (e.issuer.addField = function (r) {
              m([r]), e.issuer.attributes.push(r);
            }),
            (e.issuer.attributes = []),
            (e.issuer.hash = null),
            (e.subject = {}),
            (e.subject.getField = function (r) {
              return _(e.subject, r);
            }),
            (e.subject.addField = function (r) {
              m([r]), e.subject.attributes.push(r);
            }),
            (e.subject.attributes = []),
            (e.subject.hash = null),
            (e.extensions = []),
            (e.publicKey = null),
            (e.md = null),
            (e.setSubject = function (r, n) {
              m(r),
                (e.subject.attributes = r),
                delete e.subject.uniqueId,
                n && (e.subject.uniqueId = n),
                (e.subject.hash = null);
            }),
            (e.setIssuer = function (r, n) {
              m(r),
                (e.issuer.attributes = r),
                delete e.issuer.uniqueId,
                n && (e.issuer.uniqueId = n),
                (e.issuer.hash = null);
            }),
            (e.setExtensions = function (r) {
              for (var n = 0; n < r.length; ++n) C(r[n], { cert: e });
              e.extensions = r;
            }),
            (e.getExtension = function (r) {
              "string" == typeof r && (r = { name: r });
              for (
                var n, a = null, s = 0;
                null === a && s < e.extensions.length;
                ++s
              )
                (n = e.extensions[s]),
                  ((r.id && n.id === r.id) || (r.name && n.name === r.name)) &&
                    (a = n);
              return a;
            }),
            (e.sign = function (r, n) {
              e.md = n || a.md.sha1.create();
              var u = c[e.md.algorithm + "WithRSAEncryption"];
              if (!u) {
                var l = Error(
                  "Could not compute certificate digest. Unknown message digest algorithm OID."
                );
                throw ((l.algorithm = e.md.algorithm), l);
              }
              (e.signatureOid = e.siginfo.algorithmOid = u),
                (e.tbsCertificate = o.getTBSCertificate(e));
              var p = s.toDer(e.tbsCertificate);
              e.md.update(p.getBytes()), (e.signature = r.sign(e.md));
            }),
            (e.verify = function (r) {
              var n = !1;
              if (!e.issued(r)) {
                var a = r.issuer,
                  c = e.subject,
                  u = Error(
                    "The parent certificate did not issue the given child certificate; the child certificate's issuer does not match the parent's subject."
                  );
                throw (
                  ((u.expectedIssuer = c.attributes),
                  (u.actualIssuer = a.attributes),
                  u)
                );
              }
              var l = r.md;
              if (null === l) {
                l = y({ signatureOid: r.signatureOid, type: "certificate" });
                var p = r.tbsCertificate || o.getTBSCertificate(r),
                  f = s.toDer(p);
                l.update(f.getBytes());
              }
              return (
                null !== l &&
                  (n = g({ certificate: e, md: l, signature: r.signature })),
                n
              );
            }),
            (e.isIssuer = function (r) {
              var n,
                a,
                s = !1,
                o = e.issuer,
                c = r.subject;
              if (o.hash && c.hash) s = o.hash === c.hash;
              else if (o.attributes.length === c.attributes.length) {
                s = !0;
                for (var u = 0; s && u < o.attributes.length; ++u)
                  (n = o.attributes[u]),
                    (a = c.attributes[u]),
                    (n.type === a.type && n.value === a.value) || (s = !1);
              }
              return s;
            }),
            (e.issued = function (r) {
              return r.isIssuer(e);
            }),
            (e.generateSubjectKeyIdentifier = function () {
              return o.getPublicKeyFingerprint(e.publicKey, {
                type: "RSAPublicKey",
              });
            }),
            (e.verifySubjectKeyIdentifier = function () {
              for (
                var r = c.subjectKeyIdentifier, n = 0;
                n < e.extensions.length;
                ++n
              ) {
                var s = e.extensions[n];
                if (s.id === r) {
                  var o = e.generateSubjectKeyIdentifier().getBytes();
                  return a.util.hexToBytes(s.subjectKeyIdentifier) === o;
                }
              }
              return !1;
            }),
            e
          );
        }),
        (o.certificateFromAsn1 = function (e, r) {
          var n = {},
            c = [];
          if (!s.validate(e, p, n, c)) {
            var u = Error(
              "Cannot read X.509 certificate. ASN.1 object is not an X509v3 Certificate."
            );
            throw ((u.errors = c), u);
          }
          if (s.derToOid(n.publicKeyOid) !== o.oids.rsaEncryption)
            throw Error("Cannot read public key. OID is not RSA.");
          var l = o.createCertificate();
          l.version = n.certVersion ? n.certVersion.charCodeAt(0) : 0;
          var f = a.util.createBuffer(n.certSerialNumber);
          (l.serialNumber = f.toHex()),
            (l.signatureOid = a.asn1.derToOid(n.certSignatureOid)),
            (l.signatureParameters = $(
              l.signatureOid,
              n.certSignatureParams,
              !0
            )),
            (l.siginfo.algorithmOid = a.asn1.derToOid(n.certinfoSignatureOid)),
            (l.siginfo.parameters = $(
              l.siginfo.algorithmOid,
              n.certinfoSignatureParams,
              !1
            )),
            (l.signature = n.certSignature);
          var h = [];
          if (
            (void 0 !== n.certValidity1UTCTime &&
              h.push(s.utcTimeToDate(n.certValidity1UTCTime)),
            void 0 !== n.certValidity2GeneralizedTime &&
              h.push(s.generalizedTimeToDate(n.certValidity2GeneralizedTime)),
            void 0 !== n.certValidity3UTCTime &&
              h.push(s.utcTimeToDate(n.certValidity3UTCTime)),
            void 0 !== n.certValidity4GeneralizedTime &&
              h.push(s.generalizedTimeToDate(n.certValidity4GeneralizedTime)),
            h.length > 2)
          )
            throw Error(
              "Cannot read notBefore/notAfter validity times; more than two times were provided in the certificate."
            );
          if (h.length < 2)
            throw Error(
              "Cannot read notBefore/notAfter validity times; they were not provided as either UTCTime or GeneralizedTime."
            );
          if (
            ((l.validity.notBefore = h[0]),
            (l.validity.notAfter = h[1]),
            (l.tbsCertificate = n.tbsCertificate),
            r)
          ) {
            l.md = y({ signatureOid: l.signatureOid, type: "certificate" });
            var d = s.toDer(l.tbsCertificate);
            l.md.update(d.getBytes());
          }
          var g = a.md.sha1.create(),
            v = s.toDer(n.certIssuer);
          g.update(v.getBytes()),
            (l.issuer.getField = function (e) {
              return _(l.issuer, e);
            }),
            (l.issuer.addField = function (e) {
              m([e]), l.issuer.attributes.push(e);
            }),
            (l.issuer.attributes = o.RDNAttributesAsArray(n.certIssuer)),
            n.certIssuerUniqueId && (l.issuer.uniqueId = n.certIssuerUniqueId),
            (l.issuer.hash = g.digest().toHex());
          var C = a.md.sha1.create(),
            E = s.toDer(n.certSubject);
          return (
            C.update(E.getBytes()),
            (l.subject.getField = function (e) {
              return _(l.subject, e);
            }),
            (l.subject.addField = function (e) {
              m([e]), l.subject.attributes.push(e);
            }),
            (l.subject.attributes = o.RDNAttributesAsArray(n.certSubject)),
            n.certSubjectUniqueId &&
              (l.subject.uniqueId = n.certSubjectUniqueId),
            (l.subject.hash = C.digest().toHex()),
            n.certExtensions
              ? (l.extensions = o.certificateExtensionsFromAsn1(
                  n.certExtensions
                ))
              : (l.extensions = []),
            (l.publicKey = o.publicKeyFromAsn1(n.subjectPublicKeyInfo)),
            l
          );
        }),
        (o.certificateExtensionsFromAsn1 = function (e) {
          for (var r = [], n = 0; n < e.value.length; ++n)
            for (var a = e.value[n], s = 0; s < a.value.length; ++s)
              r.push(o.certificateExtensionFromAsn1(a.value[s]));
          return r;
        }),
        (o.certificateExtensionFromAsn1 = function (e) {
          var r,
            n = {};
          if (
            ((n.id = s.derToOid(e.value[0].value)),
            (n.critical = !1),
            e.value[1].type === s.Type.BOOLEAN
              ? ((n.critical = 0 !== e.value[1].value.charCodeAt(0)),
                (n.value = e.value[2].value))
              : (n.value = e.value[1].value),
            n.id in c)
          ) {
            if (((n.name = c[n.id]), "keyUsage" === n.name)) {
              var o = 0,
                u = 0;
              (p = s.fromDer(n.value)).value.length > 1 &&
                ((o = p.value.charCodeAt(1)),
                (u = p.value.length > 2 ? p.value.charCodeAt(2) : 0)),
                (n.digitalSignature = 128 == (128 & o)),
                (n.nonRepudiation = 64 == (64 & o)),
                (n.keyEncipherment = 32 == (32 & o)),
                (n.dataEncipherment = 16 == (16 & o)),
                (n.keyAgreement = 8 == (8 & o)),
                (n.keyCertSign = 4 == (4 & o)),
                (n.cRLSign = 2 == (2 & o)),
                (n.encipherOnly = 1 == (1 & o)),
                (n.decipherOnly = 128 == (128 & u));
            } else if ("basicConstraints" === n.name) {
              (p = s.fromDer(n.value)).value.length > 0 &&
              p.value[0].type === s.Type.BOOLEAN
                ? (n.cA = 0 !== p.value[0].value.charCodeAt(0))
                : (n.cA = !1);
              var l = null;
              p.value.length > 0 && p.value[0].type === s.Type.INTEGER
                ? (l = p.value[0].value)
                : p.value.length > 1 && (l = p.value[1].value),
                null !== l && (n.pathLenConstraint = s.derToInteger(l));
            } else if ("extKeyUsage" === n.name)
              for (var p = s.fromDer(n.value), f = 0; f < p.value.length; ++f) {
                var h = s.derToOid(p.value[f].value);
                h in c ? (n[c[h]] = !0) : (n[h] = !0);
              }
            else if ("nsCertType" === n.name)
              (o = 0),
                (p = s.fromDer(n.value)).value.length > 1 &&
                  (o = p.value.charCodeAt(1)),
                (n.client = 128 == (128 & o)),
                (n.server = 64 == (64 & o)),
                (n.email = 32 == (32 & o)),
                (n.objsign = 16 == (16 & o)),
                (n.reserved = 8 == (8 & o)),
                (n.sslCA = 4 == (4 & o)),
                (n.emailCA = 2 == (2 & o)),
                (n.objCA = 1 == (1 & o));
            else if (
              "subjectAltName" === n.name ||
              "issuerAltName" === n.name
            ) {
              (n.altNames = []), (p = s.fromDer(n.value));
              for (var d = 0; d < p.value.length; ++d) {
                var _ = { type: (r = p.value[d]).type, value: r.value };
                switch ((n.altNames.push(_), r.type)) {
                  case 1:
                  case 2:
                  case 6:
                    break;
                  case 7:
                    _.ip = a.util.bytesToIP(r.value);
                    break;
                  case 8:
                    _.oid = s.derToOid(r.value);
                }
              }
            } else
              "subjectKeyIdentifier" === n.name &&
                ((p = s.fromDer(n.value)),
                (n.subjectKeyIdentifier = a.util.bytesToHex(p.value)));
          }
          return n;
        }),
        (o.certificationRequestFromAsn1 = function (e, r) {
          var n = {},
            c = [];
          if (!s.validate(e, d, n, c)) {
            var u = Error(
              "Cannot read PKCS#10 certificate request. ASN.1 object is not a PKCS#10 CertificationRequest."
            );
            throw ((u.errors = c), u);
          }
          if (s.derToOid(n.publicKeyOid) !== o.oids.rsaEncryption)
            throw Error("Cannot read public key. OID is not RSA.");
          var l = o.createCertificationRequest();
          if (
            ((l.version = n.csrVersion ? n.csrVersion.charCodeAt(0) : 0),
            (l.signatureOid = a.asn1.derToOid(n.csrSignatureOid)),
            (l.signatureParameters = $(
              l.signatureOid,
              n.csrSignatureParams,
              !0
            )),
            (l.siginfo.algorithmOid = a.asn1.derToOid(n.csrSignatureOid)),
            (l.siginfo.parameters = $(
              l.siginfo.algorithmOid,
              n.csrSignatureParams,
              !1
            )),
            (l.signature = n.csrSignature),
            (l.certificationRequestInfo = n.certificationRequestInfo),
            r)
          ) {
            l.md = y({
              signatureOid: l.signatureOid,
              type: "certification request",
            });
            var p = s.toDer(l.certificationRequestInfo);
            l.md.update(p.getBytes());
          }
          var f = a.md.sha1.create();
          return (
            (l.subject.getField = function (e) {
              return _(l.subject, e);
            }),
            (l.subject.addField = function (e) {
              m([e]), l.subject.attributes.push(e);
            }),
            (l.subject.attributes = o.RDNAttributesAsArray(
              n.certificationRequestInfoSubject,
              f
            )),
            (l.subject.hash = f.digest().toHex()),
            (l.publicKey = o.publicKeyFromAsn1(n.subjectPublicKeyInfo)),
            (l.getAttribute = function (e) {
              return _(l, e);
            }),
            (l.addAttribute = function (e) {
              m([e]), l.attributes.push(e);
            }),
            (l.attributes = o.CRIAttributesAsArray(
              n.certificationRequestInfoAttributes || []
            )),
            l
          );
        }),
        (o.createCertificationRequest = function () {
          var e = {
            version: 0,
            signatureOid: null,
            signature: null,
            siginfo: {},
          };
          return (
            (e.siginfo.algorithmOid = null),
            (e.subject = {}),
            (e.subject.getField = function (r) {
              return _(e.subject, r);
            }),
            (e.subject.addField = function (r) {
              m([r]), e.subject.attributes.push(r);
            }),
            (e.subject.attributes = []),
            (e.subject.hash = null),
            (e.publicKey = null),
            (e.attributes = []),
            (e.getAttribute = function (r) {
              return _(e, r);
            }),
            (e.addAttribute = function (r) {
              m([r]), e.attributes.push(r);
            }),
            (e.md = null),
            (e.setSubject = function (r) {
              m(r), (e.subject.attributes = r), (e.subject.hash = null);
            }),
            (e.setAttributes = function (r) {
              m(r), (e.attributes = r);
            }),
            (e.sign = function (r, n) {
              e.md = n || a.md.sha1.create();
              var u = c[e.md.algorithm + "WithRSAEncryption"];
              if (!u) {
                var l = Error(
                  "Could not compute certification request digest. Unknown message digest algorithm OID."
                );
                throw ((l.algorithm = e.md.algorithm), l);
              }
              (e.signatureOid = e.siginfo.algorithmOid = u),
                (e.certificationRequestInfo = o.getCertificationRequestInfo(e));
              var p = s.toDer(e.certificationRequestInfo);
              e.md.update(p.getBytes()), (e.signature = r.sign(e.md));
            }),
            (e.verify = function () {
              var r = !1,
                n = e.md;
              if (null === n) {
                n = y({
                  signatureOid: e.signatureOid,
                  type: "certification request",
                });
                var a =
                    e.certificationRequestInfo ||
                    o.getCertificationRequestInfo(e),
                  c = s.toDer(a);
                n.update(c.getBytes());
              }
              return (
                null !== n &&
                  (r = g({ certificate: e, md: n, signature: e.signature })),
                r
              );
            }),
            e
          );
        });
      var S = new Date("1950-01-01T00:00:00Z"),
        T = new Date("2050-01-01T00:00:00Z");
      function B(e) {
        return e >= S && e < T
          ? s.create(s.Class.UNIVERSAL, s.Type.UTCTIME, !1, s.dateToUtcTime(e))
          : s.create(
              s.Class.UNIVERSAL,
              s.Type.GENERALIZEDTIME,
              !1,
              s.dateToGeneralizedTime(e)
            );
      }
      (o.getTBSCertificate = function (e) {
        var r = B(e.validity.notBefore),
          n = B(e.validity.notAfter),
          c = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
            s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
              s.create(
                s.Class.UNIVERSAL,
                s.Type.INTEGER,
                !1,
                s.integerToDer(e.version).getBytes()
              ),
            ]),
            s.create(
              s.Class.UNIVERSAL,
              s.Type.INTEGER,
              !1,
              a.util.hexToBytes(e.serialNumber)
            ),
            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
              s.create(
                s.Class.UNIVERSAL,
                s.Type.OID,
                !1,
                s.oidToDer(e.siginfo.algorithmOid).getBytes()
              ),
              E(e.siginfo.algorithmOid, e.siginfo.parameters),
            ]),
            v(e.issuer),
            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [r, n]),
            v(e.subject),
            o.publicKeyToAsn1(e.publicKey),
          ]);
        return (
          e.issuer.uniqueId &&
            c.value.push(
              s.create(s.Class.CONTEXT_SPECIFIC, 1, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.BITSTRING,
                  !1,
                  "\0" + e.issuer.uniqueId
                ),
              ])
            ),
          e.subject.uniqueId &&
            c.value.push(
              s.create(s.Class.CONTEXT_SPECIFIC, 2, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.BITSTRING,
                  !1,
                  "\0" + e.subject.uniqueId
                ),
              ])
            ),
          e.extensions.length > 0 &&
            c.value.push(o.certificateExtensionsToAsn1(e.extensions)),
          c
        );
      }),
        (o.getCertificationRequestInfo = function (e) {
          return s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
            s.create(
              s.Class.UNIVERSAL,
              s.Type.INTEGER,
              !1,
              s.integerToDer(e.version).getBytes()
            ),
            v(e.subject),
            o.publicKeyToAsn1(e.publicKey),
            (function e(r) {
              var n = s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, []);
              if (0 === r.attributes.length) return n;
              for (var o = r.attributes, c = 0; c < o.length; ++c) {
                var u = o[c],
                  l = u.value,
                  p = s.Type.UTF8;
                "valueTagClass" in u && (p = u.valueTagClass),
                  p === s.Type.UTF8 && (l = a.util.encodeUtf8(l));
                var f = !1;
                "valueConstructed" in u && (f = u.valueConstructed);
                var h = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                  s.create(
                    s.Class.UNIVERSAL,
                    s.Type.OID,
                    !1,
                    s.oidToDer(u.type).getBytes()
                  ),
                  s.create(s.Class.UNIVERSAL, s.Type.SET, !0, [
                    s.create(s.Class.UNIVERSAL, p, f, l),
                  ]),
                ]);
                n.value.push(h);
              }
              return n;
            })(e),
          ]);
        }),
        (o.distinguishedNameToAsn1 = function (e) {
          return v(e);
        }),
        (o.certificateToAsn1 = function (e) {
          var r = e.tbsCertificate || o.getTBSCertificate(e);
          return s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
            r,
            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
              s.create(
                s.Class.UNIVERSAL,
                s.Type.OID,
                !1,
                s.oidToDer(e.signatureOid).getBytes()
              ),
              E(e.signatureOid, e.signatureParameters),
            ]),
            s.create(
              s.Class.UNIVERSAL,
              s.Type.BITSTRING,
              !1,
              "\0" + e.signature
            ),
          ]);
        }),
        (o.certificateExtensionsToAsn1 = function (e) {
          var r = s.create(s.Class.CONTEXT_SPECIFIC, 3, !0, []),
            n = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, []);
          r.value.push(n);
          for (var a = 0; a < e.length; ++a)
            n.value.push(o.certificateExtensionToAsn1(e[a]));
          return r;
        }),
        (o.certificateExtensionToAsn1 = function (e) {
          var r = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, []);
          r.value.push(
            s.create(
              s.Class.UNIVERSAL,
              s.Type.OID,
              !1,
              s.oidToDer(e.id).getBytes()
            )
          ),
            e.critical &&
              r.value.push(
                s.create(s.Class.UNIVERSAL, s.Type.BOOLEAN, !1, "\xff")
              );
          var n = e.value;
          return (
            "string" != typeof e.value && (n = s.toDer(n).getBytes()),
            r.value.push(
              s.create(s.Class.UNIVERSAL, s.Type.OCTETSTRING, !1, n)
            ),
            r
          );
        }),
        (o.certificationRequestToAsn1 = function (e) {
          var r =
            e.certificationRequestInfo || o.getCertificationRequestInfo(e);
          return s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
            r,
            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
              s.create(
                s.Class.UNIVERSAL,
                s.Type.OID,
                !1,
                s.oidToDer(e.signatureOid).getBytes()
              ),
              E(e.signatureOid, e.signatureParameters),
            ]),
            s.create(
              s.Class.UNIVERSAL,
              s.Type.BITSTRING,
              !1,
              "\0" + e.signature
            ),
          ]);
        }),
        (o.createCaStore = function (e) {
          var r = { certs: {} };
          function n(e) {
            return c(e), r.certs[e.hash] || null;
          }
          function c(e) {
            if (!e.hash) {
              var r = a.md.sha1.create();
              (e.attributes = o.RDNAttributesAsArray(v(e), r)),
                (e.hash = r.digest().toHex());
            }
          }
          if (
            ((r.getIssuer = function (e) {
              return n(e.issuer);
            }),
            (r.addCertificate = function (e) {
              if (
                ("string" == typeof e && (e = a.pki.certificateFromPem(e)),
                c(e.subject),
                !r.hasCertificate(e))
              ) {
                if (e.subject.hash in r.certs) {
                  var n = r.certs[e.subject.hash];
                  a.util.isArray(n) || (n = [n]),
                    n.push(e),
                    (r.certs[e.subject.hash] = n);
                } else r.certs[e.subject.hash] = e;
              }
            }),
            (r.hasCertificate = function (e) {
              "string" == typeof e && (e = a.pki.certificateFromPem(e));
              var r = n(e.subject);
              if (!r) return !1;
              a.util.isArray(r) || (r = [r]);
              for (
                var c = s.toDer(o.certificateToAsn1(e)).getBytes(), u = 0;
                u < r.length;
                ++u
              )
                if (c === s.toDer(o.certificateToAsn1(r[u])).getBytes())
                  return !0;
              return !1;
            }),
            (r.listAllCertificates = function () {
              var e = [];
              for (var n in r.certs)
                if (r.certs.hasOwnProperty(n)) {
                  var s = r.certs[n];
                  if (a.util.isArray(s))
                    for (var o = 0; o < s.length; ++o) e.push(s[o]);
                  else e.push(s);
                }
              return e;
            }),
            (r.removeCertificate = function (e) {
              if (
                ("string" == typeof e && (e = a.pki.certificateFromPem(e)),
                c(e.subject),
                !r.hasCertificate(e))
              )
                return null;
              var u,
                l = n(e.subject);
              if (!a.util.isArray(l))
                return (
                  (u = r.certs[e.subject.hash]),
                  delete r.certs[e.subject.hash],
                  u
                );
              for (
                var p = s.toDer(o.certificateToAsn1(e)).getBytes(), f = 0;
                f < l.length;
                ++f
              )
                p === s.toDer(o.certificateToAsn1(l[f])).getBytes() &&
                  ((u = l[f]), l.splice(f, 1));
              return 0 === l.length && delete r.certs[e.subject.hash], u;
            }),
            e)
          )
            for (var u = 0; u < e.length; ++u) {
              var l = e[u];
              r.addCertificate(l);
            }
          return r;
        }),
        (o.certificateError = {
          bad_certificate: "forge.pki.BadCertificate",
          unsupported_certificate: "forge.pki.UnsupportedCertificate",
          certificate_revoked: "forge.pki.CertificateRevoked",
          certificate_expired: "forge.pki.CertificateExpired",
          certificate_unknown: "forge.pki.CertificateUnknown",
          unknown_ca: "forge.pki.UnknownCertificateAuthority",
        }),
        (o.verifyCertificateChain = function (e, r, n) {
          "function" == typeof n && (n = { verify: n }), (n = n || {});
          var s = (r = r.slice(0)).slice(0),
            c = n.validityCheckDate;
          void 0 === c && (c = new Date());
          var u = !0,
            l = null,
            p = 0;
          do {
            var f = r.shift(),
              h = null,
              d = !1;
            if (
              (c &&
                (c < f.validity.notBefore || c > f.validity.notAfter) &&
                (l = {
                  message: "Certificate is not valid yet or has expired.",
                  error: o.certificateError.certificate_expired,
                  notBefore: f.validity.notBefore,
                  notAfter: f.validity.notAfter,
                  now: c,
                }),
              null === l)
            ) {
              if (
                (null === (h = r[0] || e.getIssuer(f)) &&
                  f.isIssuer(f) &&
                  ((d = !0), (h = f)),
                h)
              ) {
                var _ = h;
                a.util.isArray(_) || (_ = [_]);
                for (var $ = !1; !$ && _.length > 0; ) {
                  h = _.shift();
                  try {
                    $ = h.verify(f);
                  } catch (y) {}
                }
                $ ||
                  (l = {
                    message: "Certificate signature is invalid.",
                    error: o.certificateError.bad_certificate,
                  });
              }
              null !== l ||
                (h && !d) ||
                e.hasCertificate(f) ||
                (l = {
                  message: "Certificate is not trusted.",
                  error: o.certificateError.unknown_ca,
                });
            }
            if (
              (null === l &&
                h &&
                !f.isIssuer(h) &&
                (l = {
                  message: "Certificate issuer is invalid.",
                  error: o.certificateError.bad_certificate,
                }),
              null === l)
            )
              for (
                var g = { keyUsage: !0, basicConstraints: !0 }, v = 0;
                null === l && v < f.extensions.length;
                ++v
              ) {
                var m = f.extensions[v];
                !m.critical ||
                  m.name in g ||
                  (l = {
                    message:
                      "Certificate has an unsupported critical extension.",
                    error: o.certificateError.unsupported_certificate,
                  });
              }
            if (null === l && (!u || (0 === r.length && (!h || d)))) {
              var C = f.getExtension("basicConstraints"),
                E = f.getExtension("keyUsage");
              null !== E &&
                ((E.keyCertSign && null !== C) ||
                  (l = {
                    message:
                      "Certificate keyUsage or basicConstraints conflict or indicate that the certificate is not a CA. If the certificate is the only one in the chain or isn't the first then the certificate must be a valid CA.",
                    error: o.certificateError.bad_certificate,
                  })),
                null !== l ||
                  null === C ||
                  C.cA ||
                  (l = {
                    message:
                      "Certificate basicConstraints indicates the certificate is not a CA.",
                    error: o.certificateError.bad_certificate,
                  }),
                null === l &&
                  null !== E &&
                  "pathLenConstraint" in C &&
                  p - 1 > C.pathLenConstraint &&
                  (l = {
                    message:
                      "Certificate basicConstraints pathLenConstraint violated.",
                    error: o.certificateError.bad_certificate,
                  });
            }
            var S = null === l || l.error,
              T = n.verify ? n.verify(S, p, s) : S;
            if (!0 !== T)
              throw (
                (!0 === S &&
                  (l = {
                    message: "The application rejected the certificate.",
                    error: o.certificateError.bad_certificate,
                  }),
                (T || 0 === T) &&
                  ("object" != typeof T || a.util.isArray(T)
                    ? "string" == typeof T && (l.error = T)
                    : (T.message && (l.message = T.message),
                      T.error && (l.error = T.error))),
                l)
              );
            (l = null), (u = !1), ++p;
          } while (r.length > 0);
          return !0;
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(2),
        n(1),
        ((e.exports = a.pss = a.pss || {}).create = function (e) {
          3 === arguments.length &&
            (e = {
              md: arguments[0],
              mgf: arguments[1],
              saltLength: arguments[2],
            });
          var r,
            n = e.md,
            s = e.mgf,
            o = n.digestLength,
            c = e.salt || null;
          if (
            ("string" == typeof c && (c = a.util.createBuffer(c)),
            "saltLength" in e)
          )
            r = e.saltLength;
          else {
            if (null === c)
              throw Error(
                "Salt length not specified or specific salt not given."
              );
            r = c.length();
          }
          if (null !== c && c.length() !== r)
            throw Error(
              "Given salt length does not match length of given salt."
            );
          var u = e.prng || a.random;
          return {
            encode: function (e, l) {
              var p,
                f,
                h = l - 1,
                d = Math.ceil(h / 8),
                _ = e.digest().getBytes();
              if (d < o + r + 2) throw Error("Message is too long to encrypt.");
              f = null === c ? u.getBytesSync(r) : c.bytes();
              var $ = new a.util.ByteBuffer();
              $.fillWithByte(0, 8),
                $.putBytes(_),
                $.putBytes(f),
                n.start(),
                n.update($.getBytes());
              var y = n.digest().getBytes(),
                g = new a.util.ByteBuffer();
              g.fillWithByte(0, d - r - o - 2), g.putByte(1), g.putBytes(f);
              var v = g.getBytes(),
                m = d - o - 1,
                C = s.generate(y, m),
                E = "";
              for (p = 0; p < m; p++)
                E += String.fromCharCode(v.charCodeAt(p) ^ C.charCodeAt(p));
              return (
                (E =
                  String.fromCharCode(
                    E.charCodeAt(0) & ~((65280 >> (8 * d - h)) & 255)
                  ) + E.substr(1)) +
                y +
                "\xbc"
              );
            },
            verify: function (e, c, u) {
              var l,
                p = u - 1,
                f = Math.ceil(p / 8);
              if (((c = c.substr(-f)), f < o + r + 2))
                throw Error(
                  "Inconsistent parameters to PSS signature verification."
                );
              if (188 !== c.charCodeAt(f - 1))
                throw Error("Encoded message does not end in 0xBC.");
              var h = f - o - 1,
                d = c.substr(0, h),
                _ = c.substr(h, o),
                $ = (65280 >> (8 * f - p)) & 255;
              if (0 != (d.charCodeAt(0) & $))
                throw Error("Bits beyond keysize not zero as expected.");
              var y = s.generate(_, h),
                g = "";
              for (l = 0; l < h; l++)
                g += String.fromCharCode(d.charCodeAt(l) ^ y.charCodeAt(l));
              g = String.fromCharCode(g.charCodeAt(0) & ~$) + g.substr(1);
              var v = f - o - r - 2;
              for (l = 0; l < v; l++)
                if (0 !== g.charCodeAt(l))
                  throw Error("Leftmost octets not zero as expected");
              if (1 !== g.charCodeAt(v))
                throw Error(
                  "Inconsistent PSS signature, 0x01 marker not found"
                );
              var m = g.substr(-r),
                C = new a.util.ByteBuffer();
              return (
                C.fillWithByte(0, 8),
                C.putBytes(e),
                C.putBytes(m),
                n.start(),
                n.update(C.getBytes()),
                _ === n.digest().getBytes()
              );
            },
          };
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(1), (a.cipher = a.cipher || {});
      var s = (e.exports = a.cipher.modes = a.cipher.modes || {});
      function o(e, r) {
        if (
          ("string" == typeof e && (e = a.util.createBuffer(e)),
          a.util.isArray(e) && e.length > 4)
        ) {
          var n = e;
          e = a.util.createBuffer();
          for (var s = 0; s < n.length; ++s) e.putByte(n[s]);
        }
        if (e.length() < r)
          throw Error(
            "Invalid IV length; got " +
              e.length() +
              " bytes and expected " +
              r +
              " bytes."
          );
        if (!a.util.isArray(e)) {
          var o = [],
            c = r / 4;
          for (s = 0; s < c; ++s) o.push(e.getInt32());
          e = o;
        }
        return e;
      }
      function c(e) {
        e[e.length - 1] = (e[e.length - 1] + 1) & 4294967295;
      }
      function u(e) {
        return [(e / 4294967296) | 0, 4294967295 & e];
      }
      (s.ecb = function (e) {
        (e = e || {}),
          (this.name = "ECB"),
          (this.cipher = e.cipher),
          (this.blockSize = e.blockSize || 16),
          (this._ints = this.blockSize / 4),
          (this._inBlock = Array(this._ints)),
          (this._outBlock = Array(this._ints));
      }),
        (s.ecb.prototype.start = function (e) {}),
        (s.ecb.prototype.encrypt = function (e, r, n) {
          if (e.length() < this.blockSize && !(n && e.length() > 0)) return !0;
          for (var a = 0; a < this._ints; ++a) this._inBlock[a] = e.getInt32();
          for (
            this.cipher.encrypt(this._inBlock, this._outBlock), a = 0;
            a < this._ints;
            ++a
          )
            r.putInt32(this._outBlock[a]);
        }),
        (s.ecb.prototype.decrypt = function (e, r, n) {
          if (e.length() < this.blockSize && !(n && e.length() > 0)) return !0;
          for (var a = 0; a < this._ints; ++a) this._inBlock[a] = e.getInt32();
          for (
            this.cipher.decrypt(this._inBlock, this._outBlock), a = 0;
            a < this._ints;
            ++a
          )
            r.putInt32(this._outBlock[a]);
        }),
        (s.ecb.prototype.pad = function (e, r) {
          var n =
            e.length() === this.blockSize
              ? this.blockSize
              : this.blockSize - e.length();
          return e.fillWithByte(n, n), !0;
        }),
        (s.ecb.prototype.unpad = function (e, r) {
          if (r.overflow > 0) return !1;
          var n = e.length(),
            a = e.at(n - 1);
          return !(a > this.blockSize << 2) && (e.truncate(a), !0);
        }),
        (s.cbc = function (e) {
          (e = e || {}),
            (this.name = "CBC"),
            (this.cipher = e.cipher),
            (this.blockSize = e.blockSize || 16),
            (this._ints = this.blockSize / 4),
            (this._inBlock = Array(this._ints)),
            (this._outBlock = Array(this._ints));
        }),
        (s.cbc.prototype.start = function (e) {
          if (null === e.iv) {
            if (!this._prev) throw Error("Invalid IV parameter.");
            this._iv = this._prev.slice(0);
          } else {
            if (!("iv" in e)) throw Error("Invalid IV parameter.");
            (this._iv = o(e.iv, this.blockSize)),
              (this._prev = this._iv.slice(0));
          }
        }),
        (s.cbc.prototype.encrypt = function (e, r, n) {
          if (e.length() < this.blockSize && !(n && e.length() > 0)) return !0;
          for (var a = 0; a < this._ints; ++a)
            this._inBlock[a] = this._prev[a] ^ e.getInt32();
          for (
            this.cipher.encrypt(this._inBlock, this._outBlock), a = 0;
            a < this._ints;
            ++a
          )
            r.putInt32(this._outBlock[a]);
          this._prev = this._outBlock;
        }),
        (s.cbc.prototype.decrypt = function (e, r, n) {
          if (e.length() < this.blockSize && !(n && e.length() > 0)) return !0;
          for (var a = 0; a < this._ints; ++a) this._inBlock[a] = e.getInt32();
          for (
            this.cipher.decrypt(this._inBlock, this._outBlock), a = 0;
            a < this._ints;
            ++a
          )
            r.putInt32(this._prev[a] ^ this._outBlock[a]);
          this._prev = this._inBlock.slice(0);
        }),
        (s.cbc.prototype.pad = function (e, r) {
          var n =
            e.length() === this.blockSize
              ? this.blockSize
              : this.blockSize - e.length();
          return e.fillWithByte(n, n), !0;
        }),
        (s.cbc.prototype.unpad = function (e, r) {
          if (r.overflow > 0) return !1;
          var n = e.length(),
            a = e.at(n - 1);
          return !(a > this.blockSize << 2) && (e.truncate(a), !0);
        }),
        (s.cfb = function (e) {
          (e = e || {}),
            (this.name = "CFB"),
            (this.cipher = e.cipher),
            (this.blockSize = e.blockSize || 16),
            (this._ints = this.blockSize / 4),
            (this._inBlock = null),
            (this._outBlock = Array(this._ints)),
            (this._partialBlock = Array(this._ints)),
            (this._partialOutput = a.util.createBuffer()),
            (this._partialBytes = 0);
        }),
        (s.cfb.prototype.start = function (e) {
          if (!("iv" in e)) throw Error("Invalid IV parameter.");
          (this._iv = o(e.iv, this.blockSize)),
            (this._inBlock = this._iv.slice(0)),
            (this._partialBytes = 0);
        }),
        (s.cfb.prototype.encrypt = function (e, r, n) {
          var a = e.length();
          if (0 === a) return !0;
          if (
            (this.cipher.encrypt(this._inBlock, this._outBlock),
            0 === this._partialBytes && a >= this.blockSize)
          )
            for (var s = 0; s < this._ints; ++s)
              (this._inBlock[s] = e.getInt32() ^ this._outBlock[s]),
                r.putInt32(this._inBlock[s]);
          else {
            var o = (this.blockSize - a) % this.blockSize;
            for (
              o > 0 && (o = this.blockSize - o),
                this._partialOutput.clear(),
                s = 0;
              s < this._ints;
              ++s
            )
              (this._partialBlock[s] = e.getInt32() ^ this._outBlock[s]),
                this._partialOutput.putInt32(this._partialBlock[s]);
            if (o > 0) e.read -= this.blockSize;
            else
              for (s = 0; s < this._ints; ++s)
                this._inBlock[s] = this._partialBlock[s];
            if (
              (this._partialBytes > 0 &&
                this._partialOutput.getBytes(this._partialBytes),
              o > 0 && !n)
            )
              return (
                r.putBytes(
                  this._partialOutput.getBytes(o - this._partialBytes)
                ),
                (this._partialBytes = o),
                !0
              );
            r.putBytes(this._partialOutput.getBytes(a - this._partialBytes)),
              (this._partialBytes = 0);
          }
        }),
        (s.cfb.prototype.decrypt = function (e, r, n) {
          var a = e.length();
          if (0 === a) return !0;
          if (
            (this.cipher.encrypt(this._inBlock, this._outBlock),
            0 === this._partialBytes && a >= this.blockSize)
          )
            for (var s = 0; s < this._ints; ++s)
              (this._inBlock[s] = e.getInt32()),
                r.putInt32(this._inBlock[s] ^ this._outBlock[s]);
          else {
            var o = (this.blockSize - a) % this.blockSize;
            for (
              o > 0 && (o = this.blockSize - o),
                this._partialOutput.clear(),
                s = 0;
              s < this._ints;
              ++s
            )
              (this._partialBlock[s] = e.getInt32()),
                this._partialOutput.putInt32(
                  this._partialBlock[s] ^ this._outBlock[s]
                );
            if (o > 0) e.read -= this.blockSize;
            else
              for (s = 0; s < this._ints; ++s)
                this._inBlock[s] = this._partialBlock[s];
            if (
              (this._partialBytes > 0 &&
                this._partialOutput.getBytes(this._partialBytes),
              o > 0 && !n)
            )
              return (
                r.putBytes(
                  this._partialOutput.getBytes(o - this._partialBytes)
                ),
                (this._partialBytes = o),
                !0
              );
            r.putBytes(this._partialOutput.getBytes(a - this._partialBytes)),
              (this._partialBytes = 0);
          }
        }),
        (s.ofb = function (e) {
          (e = e || {}),
            (this.name = "OFB"),
            (this.cipher = e.cipher),
            (this.blockSize = e.blockSize || 16),
            (this._ints = this.blockSize / 4),
            (this._inBlock = null),
            (this._outBlock = Array(this._ints)),
            (this._partialOutput = a.util.createBuffer()),
            (this._partialBytes = 0);
        }),
        (s.ofb.prototype.start = function (e) {
          if (!("iv" in e)) throw Error("Invalid IV parameter.");
          (this._iv = o(e.iv, this.blockSize)),
            (this._inBlock = this._iv.slice(0)),
            (this._partialBytes = 0);
        }),
        (s.ofb.prototype.encrypt = function (e, r, n) {
          var a = e.length();
          if (0 === e.length()) return !0;
          if (
            (this.cipher.encrypt(this._inBlock, this._outBlock),
            0 === this._partialBytes && a >= this.blockSize)
          )
            for (var s = 0; s < this._ints; ++s)
              r.putInt32(e.getInt32() ^ this._outBlock[s]),
                (this._inBlock[s] = this._outBlock[s]);
          else {
            var o = (this.blockSize - a) % this.blockSize;
            for (
              o > 0 && (o = this.blockSize - o),
                this._partialOutput.clear(),
                s = 0;
              s < this._ints;
              ++s
            )
              this._partialOutput.putInt32(e.getInt32() ^ this._outBlock[s]);
            if (o > 0) e.read -= this.blockSize;
            else
              for (s = 0; s < this._ints; ++s)
                this._inBlock[s] = this._outBlock[s];
            if (
              (this._partialBytes > 0 &&
                this._partialOutput.getBytes(this._partialBytes),
              o > 0 && !n)
            )
              return (
                r.putBytes(
                  this._partialOutput.getBytes(o - this._partialBytes)
                ),
                (this._partialBytes = o),
                !0
              );
            r.putBytes(this._partialOutput.getBytes(a - this._partialBytes)),
              (this._partialBytes = 0);
          }
        }),
        (s.ofb.prototype.decrypt = s.ofb.prototype.encrypt),
        (s.ctr = function (e) {
          (e = e || {}),
            (this.name = "CTR"),
            (this.cipher = e.cipher),
            (this.blockSize = e.blockSize || 16),
            (this._ints = this.blockSize / 4),
            (this._inBlock = null),
            (this._outBlock = Array(this._ints)),
            (this._partialOutput = a.util.createBuffer()),
            (this._partialBytes = 0);
        }),
        (s.ctr.prototype.start = function (e) {
          if (!("iv" in e)) throw Error("Invalid IV parameter.");
          (this._iv = o(e.iv, this.blockSize)),
            (this._inBlock = this._iv.slice(0)),
            (this._partialBytes = 0);
        }),
        (s.ctr.prototype.encrypt = function (e, r, n) {
          var a = e.length();
          if (0 === a) return !0;
          if (
            (this.cipher.encrypt(this._inBlock, this._outBlock),
            0 === this._partialBytes && a >= this.blockSize)
          )
            for (var s = 0; s < this._ints; ++s)
              r.putInt32(e.getInt32() ^ this._outBlock[s]);
          else {
            var o = (this.blockSize - a) % this.blockSize;
            for (
              o > 0 && (o = this.blockSize - o),
                this._partialOutput.clear(),
                s = 0;
              s < this._ints;
              ++s
            )
              this._partialOutput.putInt32(e.getInt32() ^ this._outBlock[s]);
            if (
              (o > 0 && (e.read -= this.blockSize),
              this._partialBytes > 0 &&
                this._partialOutput.getBytes(this._partialBytes),
              o > 0 && !n)
            )
              return (
                r.putBytes(
                  this._partialOutput.getBytes(o - this._partialBytes)
                ),
                (this._partialBytes = o),
                !0
              );
            r.putBytes(this._partialOutput.getBytes(a - this._partialBytes)),
              (this._partialBytes = 0);
          }
          c(this._inBlock);
        }),
        (s.ctr.prototype.decrypt = s.ctr.prototype.encrypt),
        (s.gcm = function (e) {
          (e = e || {}),
            (this.name = "GCM"),
            (this.cipher = e.cipher),
            (this.blockSize = e.blockSize || 16),
            (this._ints = this.blockSize / 4),
            (this._inBlock = Array(this._ints)),
            (this._outBlock = Array(this._ints)),
            (this._partialOutput = a.util.createBuffer()),
            (this._partialBytes = 0),
            (this._R = 3774873600);
        }),
        (s.gcm.prototype.start = function (e) {
          if (!("iv" in e)) throw Error("Invalid IV parameter.");
          var r,
            n = a.util.createBuffer(e.iv);
          if (
            ((this._cipherLength = 0),
            (r =
              "additionalData" in e
                ? a.util.createBuffer(e.additionalData)
                : a.util.createBuffer()),
            (this._tagLength = "tagLength" in e ? e.tagLength : 128),
            (this._tag = null),
            e.decrypt &&
              ((this._tag = a.util.createBuffer(e.tag).getBytes()),
              this._tag.length !== this._tagLength / 8))
          )
            throw Error("Authentication tag does not match tag length.");
          (this._hashBlock = Array(this._ints)),
            (this.tag = null),
            (this._hashSubkey = Array(this._ints)),
            this.cipher.encrypt([0, 0, 0, 0], this._hashSubkey),
            (this.componentBits = 4),
            (this._m = this.generateHashTable(
              this._hashSubkey,
              this.componentBits
            ));
          var s = n.length();
          if (12 === s)
            this._j0 = [n.getInt32(), n.getInt32(), n.getInt32(), 1];
          else {
            for (this._j0 = [0, 0, 0, 0]; n.length() > 0; )
              this._j0 = this.ghash(this._hashSubkey, this._j0, [
                n.getInt32(),
                n.getInt32(),
                n.getInt32(),
                n.getInt32(),
              ]);
            this._j0 = this.ghash(
              this._hashSubkey,
              this._j0,
              [0, 0].concat(u(8 * s))
            );
          }
          (this._inBlock = this._j0.slice(0)),
            c(this._inBlock),
            (this._partialBytes = 0),
            (r = a.util.createBuffer(r)),
            (this._aDataLength = u(8 * r.length()));
          var o = r.length() % this.blockSize;
          for (
            o && r.fillWithByte(0, this.blockSize - o), this._s = [0, 0, 0, 0];
            r.length() > 0;

          )
            this._s = this.ghash(this._hashSubkey, this._s, [
              r.getInt32(),
              r.getInt32(),
              r.getInt32(),
              r.getInt32(),
            ]);
        }),
        (s.gcm.prototype.encrypt = function (e, r, n) {
          var a = e.length();
          if (0 === a) return !0;
          if (
            (this.cipher.encrypt(this._inBlock, this._outBlock),
            0 === this._partialBytes && a >= this.blockSize)
          ) {
            for (var s = 0; s < this._ints; ++s)
              r.putInt32((this._outBlock[s] ^= e.getInt32()));
            this._cipherLength += this.blockSize;
          } else {
            var o = (this.blockSize - a) % this.blockSize;
            for (
              o > 0 && (o = this.blockSize - o),
                this._partialOutput.clear(),
                s = 0;
              s < this._ints;
              ++s
            )
              this._partialOutput.putInt32(e.getInt32() ^ this._outBlock[s]);
            if (o <= 0 || n) {
              if (n) {
                var u = a % this.blockSize;
                (this._cipherLength += u),
                  this._partialOutput.truncate(this.blockSize - u);
              } else this._cipherLength += this.blockSize;
              for (s = 0; s < this._ints; ++s)
                this._outBlock[s] = this._partialOutput.getInt32();
              this._partialOutput.read -= this.blockSize;
            }
            if (
              (this._partialBytes > 0 &&
                this._partialOutput.getBytes(this._partialBytes),
              o > 0 && !n)
            )
              return (
                (e.read -= this.blockSize),
                r.putBytes(
                  this._partialOutput.getBytes(o - this._partialBytes)
                ),
                (this._partialBytes = o),
                !0
              );
            r.putBytes(this._partialOutput.getBytes(a - this._partialBytes)),
              (this._partialBytes = 0);
          }
          (this._s = this.ghash(this._hashSubkey, this._s, this._outBlock)),
            c(this._inBlock);
        }),
        (s.gcm.prototype.decrypt = function (e, r, n) {
          var a = e.length();
          if (a < this.blockSize && !(n && a > 0)) return !0;
          this.cipher.encrypt(this._inBlock, this._outBlock),
            c(this._inBlock),
            (this._hashBlock[0] = e.getInt32()),
            (this._hashBlock[1] = e.getInt32()),
            (this._hashBlock[2] = e.getInt32()),
            (this._hashBlock[3] = e.getInt32()),
            (this._s = this.ghash(this._hashSubkey, this._s, this._hashBlock));
          for (var s = 0; s < this._ints; ++s)
            r.putInt32(this._outBlock[s] ^ this._hashBlock[s]);
          a < this.blockSize
            ? (this._cipherLength += a % this.blockSize)
            : (this._cipherLength += this.blockSize);
        }),
        (s.gcm.prototype.afterFinish = function (e, r) {
          var n = !0;
          r.decrypt && r.overflow && e.truncate(this.blockSize - r.overflow),
            (this.tag = a.util.createBuffer());
          var s = this._aDataLength.concat(u(8 * this._cipherLength));
          this._s = this.ghash(this._hashSubkey, this._s, s);
          var o = [];
          this.cipher.encrypt(this._j0, o);
          for (var c = 0; c < this._ints; ++c)
            this.tag.putInt32(this._s[c] ^ o[c]);
          return (
            this.tag.truncate(this.tag.length() % (this._tagLength / 8)),
            r.decrypt && this.tag.bytes() !== this._tag && (n = !1),
            n
          );
        }),
        (s.gcm.prototype.multiply = function (e, r) {
          for (var n = [0, 0, 0, 0], a = r.slice(0), s = 0; s < 128; ++s)
            e[(s / 32) | 0] & (1 << (31 - (s % 32))) &&
              ((n[0] ^= a[0]), (n[1] ^= a[1]), (n[2] ^= a[2]), (n[3] ^= a[3])),
              this.pow(a, a);
          return n;
        }),
        (s.gcm.prototype.pow = function (e, r) {
          for (var n = 1 & e[3], a = 3; a > 0; --a)
            r[a] = (e[a] >>> 1) | ((1 & e[a - 1]) << 31);
          (r[0] = e[0] >>> 1), n && (r[0] ^= this._R);
        }),
        (s.gcm.prototype.tableMultiply = function (e) {
          for (var r = [0, 0, 0, 0], n = 0; n < 32; ++n) {
            var a = (e[(n / 8) | 0] >>> (4 * (7 - (n % 8)))) & 15,
              s = this._m[n][a];
            (r[0] ^= s[0]), (r[1] ^= s[1]), (r[2] ^= s[2]), (r[3] ^= s[3]);
          }
          return r;
        }),
        (s.gcm.prototype.ghash = function (e, r, n) {
          return (
            (r[0] ^= n[0]),
            (r[1] ^= n[1]),
            (r[2] ^= n[2]),
            (r[3] ^= n[3]),
            this.tableMultiply(r)
          );
        }),
        (s.gcm.prototype.generateHashTable = function (e, r) {
          for (
            var n = 8 / r, a = 4 * n, s = 16 * n, o = Array(s), c = 0;
            c < s;
            ++c
          ) {
            var u = [0, 0, 0, 0],
              l = (a - 1 - (c % a)) * r;
            (u[(c / a) | 0] = (1 << (r - 1)) << l),
              (o[c] = this.generateSubHashTable(this.multiply(u, e), r));
          }
          return o;
        }),
        (s.gcm.prototype.generateSubHashTable = function (e, r) {
          var n = 1 << r,
            a = n >>> 1,
            s = Array(n);
          s[a] = e.slice(0);
          for (var o = a >>> 1; o > 0; )
            this.pow(s[2 * o], (s[o] = [])), (o >>= 1);
          for (o = 2; o < a; ) {
            for (var c = 1; c < o; ++c) {
              var u = s[o],
                l = s[c];
              s[o + c] = [u[0] ^ l[0], u[1] ^ l[1], u[2] ^ l[2], u[3] ^ l[3]];
            }
            o *= 2;
          }
          for (s[0] = [0, 0, 0, 0], o = a + 1; o < n; ++o) {
            var p = s[o ^ a];
            s[o] = [e[0] ^ p[0], e[1] ^ p[1], e[2] ^ p[2], e[3] ^ p[3]];
          }
          return s;
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(3), n(8), n(14), n(7), n(21), n(2), n(9), n(1);
      var s = function (e, r, n, s) {
          var o = a.util.createBuffer(),
            c = e.length >> 1,
            u = c + (1 & e.length),
            l = e.substr(0, u),
            p = e.substr(c, u),
            f = a.util.createBuffer(),
            h = a.hmac.create();
          n = r + n;
          var d = Math.ceil(s / 16),
            _ = Math.ceil(s / 20);
          h.start("MD5", l);
          var $ = a.util.createBuffer();
          f.putBytes(n);
          for (var y = 0; y < d; ++y)
            h.start(null, null),
              h.update(f.getBytes()),
              f.putBuffer(h.digest()),
              h.start(null, null),
              h.update(f.bytes() + n),
              $.putBuffer(h.digest());
          h.start("SHA1", p);
          var g = a.util.createBuffer();
          for (f.clear(), f.putBytes(n), y = 0; y < _; ++y)
            h.start(null, null),
              h.update(f.getBytes()),
              f.putBuffer(h.digest()),
              h.start(null, null),
              h.update(f.bytes() + n),
              g.putBuffer(h.digest());
          return o.putBytes(a.util.xorBytes($.getBytes(), g.getBytes(), s)), o;
        },
        o = function (e, r, n) {
          var s = !1;
          try {
            var o = e.deflate(r.fragment.getBytes());
            (r.fragment = a.util.createBuffer(o)),
              (r.length = o.length),
              (s = !0);
          } catch (c) {}
          return s;
        },
        c = function (e, r, n) {
          var s = !1;
          try {
            var o = e.inflate(r.fragment.getBytes());
            (r.fragment = a.util.createBuffer(o)),
              (r.length = o.length),
              (s = !0);
          } catch (c) {}
          return s;
        },
        u = function (e, r) {
          var n = 0;
          switch (r) {
            case 1:
              n = e.getByte();
              break;
            case 2:
              n = e.getInt16();
              break;
            case 3:
              n = e.getInt24();
              break;
            case 4:
              n = e.getInt32();
          }
          return a.util.createBuffer(e.getBytes(n));
        },
        l = function (e, r, n) {
          e.putInt(n.length(), r << 3), e.putBuffer(n);
        },
        p = {
          Versions: {
            TLS_1_0: { major: 3, minor: 1 },
            TLS_1_1: { major: 3, minor: 2 },
            TLS_1_2: { major: 3, minor: 3 },
          },
        };
      (p.SupportedVersions = [p.Versions.TLS_1_1, p.Versions.TLS_1_0]),
        (p.Version = p.SupportedVersions[0]),
        (p.MaxFragment = 15360),
        (p.ConnectionEnd = { server: 0, client: 1 }),
        (p.PRFAlgorithm = { tls_prf_sha256: 0 }),
        (p.BulkCipherAlgorithm = { none: null, rc4: 0, des3: 1, aes: 2 }),
        (p.CipherType = { stream: 0, block: 1, aead: 2 }),
        (p.MACAlgorithm = {
          none: null,
          hmac_md5: 0,
          hmac_sha1: 1,
          hmac_sha256: 2,
          hmac_sha384: 3,
          hmac_sha512: 4,
        }),
        (p.CompressionMethod = { none: 0, deflate: 1 }),
        (p.ContentType = {
          change_cipher_spec: 20,
          alert: 21,
          handshake: 22,
          application_data: 23,
          heartbeat: 24,
        }),
        (p.HandshakeType = {
          hello_request: 0,
          client_hello: 1,
          server_hello: 2,
          certificate: 11,
          server_key_exchange: 12,
          certificate_request: 13,
          server_hello_done: 14,
          certificate_verify: 15,
          client_key_exchange: 16,
          finished: 20,
        }),
        (p.Alert = {}),
        (p.Alert.Level = { warning: 1, fatal: 2 }),
        (p.Alert.Description = {
          close_notify: 0,
          unexpected_message: 10,
          bad_record_mac: 20,
          decryption_failed: 21,
          record_overflow: 22,
          decompression_failure: 30,
          handshake_failure: 40,
          bad_certificate: 42,
          unsupported_certificate: 43,
          certificate_revoked: 44,
          certificate_expired: 45,
          certificate_unknown: 46,
          illegal_parameter: 47,
          unknown_ca: 48,
          access_denied: 49,
          decode_error: 50,
          decrypt_error: 51,
          export_restriction: 60,
          protocol_version: 70,
          insufficient_security: 71,
          internal_error: 80,
          user_canceled: 90,
          no_renegotiation: 100,
        }),
        (p.HeartbeatMessageType = {
          heartbeat_request: 1,
          heartbeat_response: 2,
        }),
        (p.CipherSuites = {}),
        (p.getCipherSuite = function (e) {
          var r = null;
          for (var n in p.CipherSuites) {
            var a = p.CipherSuites[n];
            if (a.id[0] === e.charCodeAt(0) && a.id[1] === e.charCodeAt(1)) {
              r = a;
              break;
            }
          }
          return r;
        }),
        (p.handleUnexpected = function (e, r) {
          (e.open || e.entity !== p.ConnectionEnd.client) &&
            e.error(e, {
              message: "Unexpected message. Received TLS record out of order.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.unexpected_message,
              },
            });
        }),
        (p.handleHelloRequest = function (e, r, n) {
          !e.handshaking &&
            e.handshakes > 0 &&
            (p.queue(
              e,
              p.createAlert(e, {
                level: p.Alert.Level.warning,
                description: p.Alert.Description.no_renegotiation,
              })
            ),
            p.flush(e)),
            e.process();
        }),
        (p.parseHelloMessage = function (e, r, n) {
          var s = null,
            o = e.entity === p.ConnectionEnd.client;
          if (n < 38)
            e.error(e, {
              message: o
                ? "Invalid ServerHello message. Message too short."
                : "Invalid ClientHello message. Message too short.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.illegal_parameter,
              },
            });
          else {
            var c = r.fragment,
              l = c.length();
            if (
              ((s = {
                version: { major: c.getByte(), minor: c.getByte() },
                random: a.util.createBuffer(c.getBytes(32)),
                session_id: u(c, 1),
                extensions: [],
              }),
              o
                ? ((s.cipher_suite = c.getBytes(2)),
                  (s.compression_method = c.getByte()))
                : ((s.cipher_suites = u(c, 2)),
                  (s.compression_methods = u(c, 1))),
              (l = n - (l - c.length())) > 0)
            ) {
              for (var f = u(c, 2); f.length() > 0; )
                s.extensions.push({
                  type: [f.getByte(), f.getByte()],
                  data: u(f, 2),
                });
              if (!o)
                for (var h = 0; h < s.extensions.length; ++h) {
                  var d = s.extensions[h];
                  if (0 === d.type[0] && 0 === d.type[1])
                    for (
                      var _ = u(d.data, 2);
                      _.length() > 0 && 0 === _.getByte();

                    )
                      e.session.extensions.server_name.serverNameList.push(
                        u(_, 2).getBytes()
                      );
                }
            }
            if (
              e.session.version &&
              (s.version.major !== e.session.version.major ||
                s.version.minor !== e.session.version.minor)
            )
              return e.error(e, {
                message:
                  "TLS version change is disallowed during renegotiation.",
                send: !0,
                alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.protocol_version,
                },
              });
            if (o) e.session.cipherSuite = p.getCipherSuite(s.cipher_suite);
            else
              for (
                var $ = a.util.createBuffer(s.cipher_suites.bytes());
                $.length() > 0 &&
                ((e.session.cipherSuite = p.getCipherSuite($.getBytes(2))),
                null === e.session.cipherSuite);

              );
            if (null === e.session.cipherSuite)
              return e.error(e, {
                message: "No cipher suites in common.",
                send: !0,
                alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.handshake_failure,
                },
                cipherSuite: a.util.bytesToHex(s.cipher_suite),
              });
            e.session.compressionMethod = o
              ? s.compression_method
              : p.CompressionMethod.none;
          }
          return s;
        }),
        (p.createSecurityParameters = function (e, r) {
          var n = e.entity === p.ConnectionEnd.client,
            a = r.random.bytes(),
            s = n ? e.session.sp.client_random : a,
            o = n ? a : p.createRandom().getBytes();
          e.session.sp = {
            entity: e.entity,
            prf_algorithm: p.PRFAlgorithm.tls_prf_sha256,
            bulk_cipher_algorithm: null,
            cipher_type: null,
            enc_key_length: null,
            block_length: null,
            fixed_iv_length: null,
            record_iv_length: null,
            mac_algorithm: null,
            mac_length: null,
            mac_key_length: null,
            compression_algorithm: e.session.compressionMethod,
            pre_master_secret: null,
            master_secret: null,
            client_random: s,
            server_random: o,
          };
        }),
        (p.handleServerHello = function (e, r, n) {
          var a = p.parseHelloMessage(e, r, n);
          if (!e.fail) {
            if (!(a.version.minor <= e.version.minor))
              return e.error(e, {
                message: "Incompatible TLS version.",
                send: !0,
                alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.protocol_version,
                },
              });
            (e.version.minor = a.version.minor),
              (e.session.version = e.version);
            var s = a.session_id.bytes();
            s.length > 0 && s === e.session.id
              ? ((e.expect = $),
                (e.session.resuming = !0),
                (e.session.sp.server_random = a.random.bytes()))
              : ((e.expect = f),
                (e.session.resuming = !1),
                p.createSecurityParameters(e, a)),
              (e.session.id = s),
              e.process();
          }
        }),
        (p.handleClientHello = function (e, r, n) {
          var s = p.parseHelloMessage(e, r, n);
          if (!e.fail) {
            var o = s.session_id.bytes(),
              c = null;
            if (
              (e.sessionCache &&
                (null === (c = e.sessionCache.getSession(o))
                  ? (o = "")
                  : (c.version.major !== s.version.major ||
                      c.version.minor > s.version.minor) &&
                    ((c = null), (o = ""))),
              0 === o.length && (o = a.random.getBytes(32)),
              (e.session.id = o),
              (e.session.clientHelloVersion = s.version),
              (e.session.sp = {}),
              c)
            )
              (e.version = e.session.version = c.version),
                (e.session.sp = c.sp);
            else {
              for (
                var u, l = 1;
                l < p.SupportedVersions.length &&
                !((u = p.SupportedVersions[l]).minor <= s.version.minor);
                ++l
              );
              (e.version = { major: u.major, minor: u.minor }),
                (e.session.version = e.version);
            }
            null !== c
              ? ((e.expect = S),
                (e.session.resuming = !0),
                (e.session.sp.client_random = s.random.bytes()))
              : ((e.expect = !1 !== e.verifyClient ? m : C),
                (e.session.resuming = !1),
                p.createSecurityParameters(e, s)),
              (e.open = !0),
              p.queue(
                e,
                p.createRecord(e, {
                  type: p.ContentType.handshake,
                  data: p.createServerHello(e),
                })
              ),
              e.session.resuming
                ? (p.queue(
                    e,
                    p.createRecord(e, {
                      type: p.ContentType.change_cipher_spec,
                      data: p.createChangeCipherSpec(),
                    })
                  ),
                  (e.state.pending = p.createConnectionState(e)),
                  (e.state.current.write = e.state.pending.write),
                  p.queue(
                    e,
                    p.createRecord(e, {
                      type: p.ContentType.handshake,
                      data: p.createFinished(e),
                    })
                  ))
                : (p.queue(
                    e,
                    p.createRecord(e, {
                      type: p.ContentType.handshake,
                      data: p.createCertificate(e),
                    })
                  ),
                  e.fail ||
                    (p.queue(
                      e,
                      p.createRecord(e, {
                        type: p.ContentType.handshake,
                        data: p.createServerKeyExchange(e),
                      })
                    ),
                    !1 !== e.verifyClient &&
                      p.queue(
                        e,
                        p.createRecord(e, {
                          type: p.ContentType.handshake,
                          data: p.createCertificateRequest(e),
                        })
                      ),
                    p.queue(
                      e,
                      p.createRecord(e, {
                        type: p.ContentType.handshake,
                        data: p.createServerHelloDone(e),
                      })
                    ))),
              p.flush(e),
              e.process();
          }
        }),
        (p.handleCertificate = function (e, r, n) {
          if (n < 3)
            return e.error(e, {
              message: "Invalid Certificate message. Message too short.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.illegal_parameter,
              },
            });
          var s,
            o,
            c = { certificate_list: u(r.fragment, 3) },
            l = [];
          try {
            for (; c.certificate_list.length() > 0; )
              (s = u(c.certificate_list, 3)),
                (o = a.asn1.fromDer(s)),
                (s = a.pki.certificateFromAsn1(o, !0)),
                l.push(s);
          } catch (f) {
            return e.error(e, {
              message: "Could not parse certificate list.",
              cause: f,
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.bad_certificate,
              },
            });
          }
          var d = e.entity === p.ConnectionEnd.client;
          (d || !0 === e.verifyClient) && 0 === l.length
            ? e.error(e, {
                message: d
                  ? "No server certificate provided."
                  : "No client certificate provided.",
                send: !0,
                alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.illegal_parameter,
                },
              })
            : 0 === l.length
            ? (e.expect = d ? h : C)
            : (d
                ? (e.session.serverCertificate = l[0])
                : (e.session.clientCertificate = l[0]),
              p.verifyCertificateChain(e, l) && (e.expect = d ? h : C)),
            e.process();
        }),
        (p.handleServerKeyExchange = function (e, r, n) {
          if (n > 0)
            return e.error(e, {
              message: "Invalid key parameters. Only RSA is supported.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.unsupported_certificate,
              },
            });
          (e.expect = d), e.process();
        }),
        (p.handleClientKeyExchange = function (e, r, n) {
          if (n < 48)
            return e.error(e, {
              message: "Invalid key parameters. Only RSA is supported.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.unsupported_certificate,
              },
            });
          var s = { enc_pre_master_secret: u(r.fragment, 2).getBytes() },
            o = null;
          if (e.getPrivateKey)
            try {
              (o = e.getPrivateKey(e, e.session.serverCertificate)),
                (o = a.pki.privateKeyFromPem(o));
            } catch (c) {
              e.error(e, {
                message: "Could not get private key.",
                cause: c,
                send: !0,
                alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.internal_error,
                },
              });
            }
          if (null === o)
            return e.error(e, {
              message: "No private key set.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.internal_error,
              },
            });
          try {
            var l = e.session.sp;
            l.pre_master_secret = o.decrypt(s.enc_pre_master_secret);
            var f = e.session.clientHelloVersion;
            if (
              f.major !== l.pre_master_secret.charCodeAt(0) ||
              f.minor !== l.pre_master_secret.charCodeAt(1)
            )
              throw Error("TLS version rollback attack detected.");
          } catch (h) {
            l.pre_master_secret = a.random.getBytes(48);
          }
          (e.expect = S),
            null !== e.session.clientCertificate && (e.expect = E),
            e.process();
        }),
        (p.handleCertificateRequest = function (e, r, n) {
          if (n < 3)
            return e.error(e, {
              message: "Invalid CertificateRequest. Message too short.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.illegal_parameter,
              },
            });
          var a = r.fragment,
            s = {
              certificate_types: u(a, 1),
              certificate_authorities: u(a, 2),
            };
          (e.session.certificateRequest = s), (e.expect = _), e.process();
        }),
        (p.handleCertificateVerify = function (e, r, n) {
          if (n < 2)
            return e.error(e, {
              message: "Invalid CertificateVerify. Message too short.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.illegal_parameter,
              },
            });
          var s = r.fragment;
          s.read -= 4;
          var o = s.bytes();
          s.read += 4;
          var c = { signature: u(s, 2).getBytes() },
            l = a.util.createBuffer();
          l.putBuffer(e.session.md5.digest()),
            l.putBuffer(e.session.sha1.digest()),
            (l = l.getBytes());
          try {
            if (
              !e.session.clientCertificate.publicKey.verify(
                l,
                c.signature,
                "NONE"
              )
            )
              throw Error("CertificateVerify signature does not match.");
            e.session.md5.update(o), e.session.sha1.update(o);
          } catch (f) {
            return e.error(e, {
              message: "Bad signature in CertificateVerify.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.handshake_failure,
              },
            });
          }
          (e.expect = S), e.process();
        }),
        (p.handleServerHelloDone = function (e, r, n) {
          if (n > 0)
            return e.error(e, {
              message: "Invalid ServerHelloDone message. Invalid length.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.record_overflow,
              },
            });
          if (null === e.serverCertificate) {
            var s = {
                message: "No server certificate provided. Not enough security.",
                send: !0,
                alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.insufficient_security,
                },
              },
              o = e.verify(e, s.alert.description, 0, []);
            if (!0 !== o)
              return (
                (o || 0 === o) &&
                  ("object" != typeof o || a.util.isArray(o)
                    ? "number" == typeof o && (s.alert.description = o)
                    : (o.message && (s.message = o.message),
                      o.alert && (s.alert.description = o.alert))),
                e.error(e, s)
              );
          }
          null !== e.session.certificateRequest &&
            ((r = p.createRecord(e, {
              type: p.ContentType.handshake,
              data: p.createCertificate(e),
            })),
            p.queue(e, r)),
            (r = p.createRecord(e, {
              type: p.ContentType.handshake,
              data: p.createClientKeyExchange(e),
            })),
            p.queue(e, r),
            (e.expect = v);
          var c = function (e, r) {
            null !== e.session.certificateRequest &&
              null !== e.session.clientCertificate &&
              p.queue(
                e,
                p.createRecord(e, {
                  type: p.ContentType.handshake,
                  data: p.createCertificateVerify(e, r),
                })
              ),
              p.queue(
                e,
                p.createRecord(e, {
                  type: p.ContentType.change_cipher_spec,
                  data: p.createChangeCipherSpec(),
                })
              ),
              (e.state.pending = p.createConnectionState(e)),
              (e.state.current.write = e.state.pending.write),
              p.queue(
                e,
                p.createRecord(e, {
                  type: p.ContentType.handshake,
                  data: p.createFinished(e),
                })
              ),
              (e.expect = $),
              p.flush(e),
              e.process();
          };
          if (
            null === e.session.certificateRequest ||
            null === e.session.clientCertificate
          )
            return c(e, null);
          p.getClientSignature(e, c);
        }),
        (p.handleChangeCipherSpec = function (e, r) {
          if (1 !== r.fragment.getByte())
            return e.error(e, {
              message: "Invalid ChangeCipherSpec message received.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.illegal_parameter,
              },
            });
          var n = e.entity === p.ConnectionEnd.client;
          ((e.session.resuming && n) || (!e.session.resuming && !n)) &&
            (e.state.pending = p.createConnectionState(e)),
            (e.state.current.read = e.state.pending.read),
            ((!e.session.resuming && n) || (e.session.resuming && !n)) &&
              (e.state.pending = null),
            (e.expect = n ? y : T),
            e.process();
        }),
        (p.handleFinished = function (e, r, n) {
          var o = r.fragment;
          o.read -= 4;
          var c = o.bytes();
          o.read += 4;
          var u = r.fragment.getBytes();
          (o = a.util.createBuffer()).putBuffer(e.session.md5.digest()),
            o.putBuffer(e.session.sha1.digest());
          var l = e.entity === p.ConnectionEnd.client;
          if (
            (o = s(
              e.session.sp.master_secret,
              l ? "server finished" : "client finished",
              o.getBytes(),
              12
            )).getBytes() !== u
          )
            return e.error(e, {
              message: "Invalid verify_data in Finished message.",
              send: !0,
              alert: {
                level: p.Alert.Level.fatal,
                description: p.Alert.Description.decrypt_error,
              },
            });
          e.session.md5.update(c),
            e.session.sha1.update(c),
            ((e.session.resuming && l) || (!e.session.resuming && !l)) &&
              (p.queue(
                e,
                p.createRecord(e, {
                  type: p.ContentType.change_cipher_spec,
                  data: p.createChangeCipherSpec(),
                })
              ),
              (e.state.current.write = e.state.pending.write),
              (e.state.pending = null),
              p.queue(
                e,
                p.createRecord(e, {
                  type: p.ContentType.handshake,
                  data: p.createFinished(e),
                })
              )),
            (e.expect = l ? g : B),
            (e.handshaking = !1),
            ++e.handshakes,
            (e.peerCertificate = l
              ? e.session.serverCertificate
              : e.session.clientCertificate),
            p.flush(e),
            (e.isConnected = !0),
            e.connected(e),
            e.process();
        }),
        (p.handleAlert = function (e, r) {
          var n,
            a = r.fragment,
            s = { level: a.getByte(), description: a.getByte() };
          switch (s.description) {
            case p.Alert.Description.close_notify:
              n = "Connection closed.";
              break;
            case p.Alert.Description.unexpected_message:
              n = "Unexpected message.";
              break;
            case p.Alert.Description.bad_record_mac:
              n = "Bad record MAC.";
              break;
            case p.Alert.Description.decryption_failed:
              n = "Decryption failed.";
              break;
            case p.Alert.Description.record_overflow:
              n = "Record overflow.";
              break;
            case p.Alert.Description.decompression_failure:
              n = "Decompression failed.";
              break;
            case p.Alert.Description.handshake_failure:
              n = "Handshake failure.";
              break;
            case p.Alert.Description.bad_certificate:
              n = "Bad certificate.";
              break;
            case p.Alert.Description.unsupported_certificate:
              n = "Unsupported certificate.";
              break;
            case p.Alert.Description.certificate_revoked:
              n = "Certificate revoked.";
              break;
            case p.Alert.Description.certificate_expired:
              n = "Certificate expired.";
              break;
            case p.Alert.Description.certificate_unknown:
              n = "Certificate unknown.";
              break;
            case p.Alert.Description.illegal_parameter:
              n = "Illegal parameter.";
              break;
            case p.Alert.Description.unknown_ca:
              n = "Unknown certificate authority.";
              break;
            case p.Alert.Description.access_denied:
              n = "Access denied.";
              break;
            case p.Alert.Description.decode_error:
              n = "Decode error.";
              break;
            case p.Alert.Description.decrypt_error:
              n = "Decrypt error.";
              break;
            case p.Alert.Description.export_restriction:
              n = "Export restriction.";
              break;
            case p.Alert.Description.protocol_version:
              n = "Unsupported protocol version.";
              break;
            case p.Alert.Description.insufficient_security:
              n = "Insufficient security.";
              break;
            case p.Alert.Description.internal_error:
              n = "Internal error.";
              break;
            case p.Alert.Description.user_canceled:
              n = "User canceled.";
              break;
            case p.Alert.Description.no_renegotiation:
              n = "Renegotiation not supported.";
              break;
            default:
              n = "Unknown error.";
          }
          if (s.description === p.Alert.Description.close_notify)
            return e.close();
          e.error(e, {
            message: n,
            send: !1,
            origin: e.entity === p.ConnectionEnd.client ? "server" : "client",
            alert: s,
          }),
            e.process();
        }),
        (p.handleHandshake = function (e, r) {
          var n = r.fragment,
            s = n.getByte(),
            o = n.getInt24();
          if (o > n.length())
            return (
              (e.fragmented = r),
              (r.fragment = a.util.createBuffer()),
              (n.read -= 4),
              e.process()
            );
          (e.fragmented = null), (n.read -= 4);
          var c = n.bytes(o + 4);
          (n.read += 4),
            s in K[e.entity][e.expect]
              ? (e.entity !== p.ConnectionEnd.server ||
                  e.open ||
                  e.fail ||
                  ((e.handshaking = !0),
                  (e.session = {
                    version: null,
                    extensions: { server_name: { serverNameList: [] } },
                    cipherSuite: null,
                    compressionMethod: null,
                    serverCertificate: null,
                    clientCertificate: null,
                    md5: a.md.md5.create(),
                    sha1: a.md.sha1.create(),
                  })),
                s !== p.HandshakeType.hello_request &&
                  s !== p.HandshakeType.certificate_verify &&
                  s !== p.HandshakeType.finished &&
                  (e.session.md5.update(c), e.session.sha1.update(c)),
                K[e.entity][e.expect][s](e, r, o))
              : p.handleUnexpected(e, r);
        }),
        (p.handleApplicationData = function (e, r) {
          e.data.putBuffer(r.fragment), e.dataReady(e), e.process();
        }),
        (p.handleHeartbeat = function (e, r) {
          var n = r.fragment,
            s = n.getByte(),
            o = n.getInt16(),
            c = n.getBytes(o);
          if (s === p.HeartbeatMessageType.heartbeat_request) {
            if (e.handshaking || o > c.length) return e.process();
            p.queue(
              e,
              p.createRecord(e, {
                type: p.ContentType.heartbeat,
                data: p.createHeartbeat(
                  p.HeartbeatMessageType.heartbeat_response,
                  c
                ),
              })
            ),
              p.flush(e);
          } else if (s === p.HeartbeatMessageType.heartbeat_response) {
            if (c !== e.expectedHeartbeatPayload) return e.process();
            e.heartbeatReceived &&
              e.heartbeatReceived(e, a.util.createBuffer(c));
          }
          e.process();
        });
      var f = 1,
        h = 2,
        d = 3,
        _ = 4,
        $ = 5,
        y = 6,
        g = 7,
        v = 8,
        m = 1,
        C = 2,
        E = 3,
        S = 4,
        T = 5,
        B = 6,
        I = p.handleUnexpected,
        A = p.handleChangeCipherSpec,
        b = p.handleAlert,
        N = p.handleHandshake,
        R = p.handleApplicationData,
        k = p.handleHeartbeat,
        L = [];
      (L[p.ConnectionEnd.client] = [
        [I, b, N, I, k],
        [I, b, N, I, k],
        [I, b, N, I, k],
        [I, b, N, I, k],
        [I, b, N, I, k],
        [A, b, I, I, k],
        [I, b, N, I, k],
        [I, b, N, R, k],
        [I, b, N, I, k],
      ]),
        (L[p.ConnectionEnd.server] = [
          [I, b, N, I, k],
          [I, b, N, I, k],
          [I, b, N, I, k],
          [I, b, N, I, k],
          [A, b, I, I, k],
          [I, b, N, I, k],
          [I, b, N, R, k],
          [I, b, N, I, k],
        ]);
      var U = p.handleHelloRequest,
        D = p.handleServerHello,
        w = p.handleCertificate,
        P = p.handleServerKeyExchange,
        x = p.handleCertificateRequest,
        V = p.handleServerHelloDone,
        O = p.handleFinished,
        K = [];
      K[p.ConnectionEnd.client] = [
        [I, I, D, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
        [U, I, I, I, I, I, I, I, I, I, I, w, P, x, V, I, I, I, I, I, I],
        [U, I, I, I, I, I, I, I, I, I, I, I, P, x, V, I, I, I, I, I, I],
        [U, I, I, I, I, I, I, I, I, I, I, I, I, x, V, I, I, I, I, I, I],
        [U, I, I, I, I, I, I, I, I, I, I, I, I, I, V, I, I, I, I, I, I],
        [U, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
        [U, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, O],
        [U, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
        [U, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
      ];
      var F = p.handleClientHello,
        M = p.handleClientKeyExchange,
        H = p.handleCertificateVerify;
      (K[p.ConnectionEnd.server] = [
        [I, F, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
        [I, I, I, I, I, I, I, I, I, I, I, w, I, I, I, I, I, I, I, I, I],
        [I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, M, I, I, I, I],
        [I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, H, I, I, I, I, I],
        [I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
        [I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, O],
        [I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
        [I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
      ]),
        (p.generateKeys = function (e, r) {
          var n = s,
            a = r.client_random + r.server_random;
          e.session.resuming ||
            ((r.master_secret = n(
              r.pre_master_secret,
              "master secret",
              a,
              48
            ).bytes()),
            (r.pre_master_secret = null)),
            (a = r.server_random + r.client_random);
          var o = 2 * r.mac_key_length + 2 * r.enc_key_length,
            c =
              e.version.major === p.Versions.TLS_1_0.major &&
              e.version.minor === p.Versions.TLS_1_0.minor;
          c && (o += 2 * r.fixed_iv_length);
          var u = n(r.master_secret, "key expansion", a, o),
            l = {
              client_write_MAC_key: u.getBytes(r.mac_key_length),
              server_write_MAC_key: u.getBytes(r.mac_key_length),
              client_write_key: u.getBytes(r.enc_key_length),
              server_write_key: u.getBytes(r.enc_key_length),
            };
          return (
            c &&
              ((l.client_write_IV = u.getBytes(r.fixed_iv_length)),
              (l.server_write_IV = u.getBytes(r.fixed_iv_length))),
            l
          );
        }),
        (p.createConnectionState = function (e) {
          var r = e.entity === p.ConnectionEnd.client,
            n = function () {
              var e = {
                sequenceNumber: [0, 0],
                macKey: null,
                macLength: 0,
                macFunction: null,
                cipherState: null,
                cipherFunction: function (e) {
                  return !0;
                },
                compressionState: null,
                compressFunction: function (e) {
                  return !0;
                },
                updateSequenceNumber: function () {
                  4294967295 === e.sequenceNumber[1]
                    ? ((e.sequenceNumber[1] = 0), ++e.sequenceNumber[0])
                    : ++e.sequenceNumber[1];
                },
              };
              return e;
            },
            a = { read: n(), write: n() };
          if (
            ((a.read.update = function (e, r) {
              return (
                a.read.cipherFunction(r, a.read)
                  ? a.read.compressFunction(e, r, a.read) ||
                    e.error(e, {
                      message: "Could not decompress record.",
                      send: !0,
                      alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.decompression_failure,
                      },
                    })
                  : e.error(e, {
                      message: "Could not decrypt record or bad MAC.",
                      send: !0,
                      alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.bad_record_mac,
                      },
                    }),
                !e.fail
              );
            }),
            (a.write.update = function (e, r) {
              return (
                a.write.compressFunction(e, r, a.write)
                  ? a.write.cipherFunction(r, a.write) ||
                    e.error(e, {
                      message: "Could not encrypt record.",
                      send: !1,
                      alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.internal_error,
                      },
                    })
                  : e.error(e, {
                      message: "Could not compress record.",
                      send: !1,
                      alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.internal_error,
                      },
                    }),
                !e.fail
              );
            }),
            e.session)
          ) {
            var s = e.session.sp;
            switch (
              (e.session.cipherSuite.initSecurityParameters(s),
              (s.keys = p.generateKeys(e, s)),
              (a.read.macKey = r
                ? s.keys.server_write_MAC_key
                : s.keys.client_write_MAC_key),
              (a.write.macKey = r
                ? s.keys.client_write_MAC_key
                : s.keys.server_write_MAC_key),
              e.session.cipherSuite.initConnectionState(a, e, s),
              s.compression_algorithm)
            ) {
              case p.CompressionMethod.none:
                break;
              case p.CompressionMethod.deflate:
                (a.read.compressFunction = c), (a.write.compressFunction = o);
                break;
              default:
                throw Error("Unsupported compression algorithm.");
            }
          }
          return a;
        }),
        (p.createRandom = function () {
          var e = new Date(),
            r = +e + 6e4 * e.getTimezoneOffset(),
            n = a.util.createBuffer();
          return n.putInt32(r), n.putBytes(a.random.getBytes(28)), n;
        }),
        (p.createRecord = function (e, r) {
          return r.data
            ? {
                type: r.type,
                version: { major: e.version.major, minor: e.version.minor },
                length: r.data.length(),
                fragment: r.data,
              }
            : null;
        }),
        (p.createAlert = function (e, r) {
          var n = a.util.createBuffer();
          return (
            n.putByte(r.level),
            n.putByte(r.description),
            p.createRecord(e, { type: p.ContentType.alert, data: n })
          );
        }),
        (p.createClientHello = function (e) {
          e.session.clientHelloVersion = {
            major: e.version.major,
            minor: e.version.minor,
          };
          for (
            var r = a.util.createBuffer(), n = 0;
            n < e.cipherSuites.length;
            ++n
          ) {
            var s = e.cipherSuites[n];
            r.putByte(s.id[0]), r.putByte(s.id[1]);
          }
          var o = r.length(),
            c = a.util.createBuffer();
          c.putByte(p.CompressionMethod.none);
          var u = c.length(),
            f = a.util.createBuffer();
          if (e.virtualHost) {
            var h = a.util.createBuffer();
            h.putByte(0), h.putByte(0);
            var d = a.util.createBuffer();
            d.putByte(0), l(d, 2, a.util.createBuffer(e.virtualHost));
            var _ = a.util.createBuffer();
            l(_, 2, d), l(h, 2, _), f.putBuffer(h);
          }
          var $ = f.length();
          $ > 0 && ($ += 2);
          var y = e.session.id,
            g = y.length + 1 + 2 + 4 + 28 + 2 + o + 1 + u + $,
            v = a.util.createBuffer();
          return (
            v.putByte(p.HandshakeType.client_hello),
            v.putInt24(g),
            v.putByte(e.version.major),
            v.putByte(e.version.minor),
            v.putBytes(e.session.sp.client_random),
            l(v, 1, a.util.createBuffer(y)),
            l(v, 2, r),
            l(v, 1, c),
            $ > 0 && l(v, 2, f),
            v
          );
        }),
        (p.createServerHello = function (e) {
          var r = e.session.id,
            n = r.length + 1 + 2 + 4 + 28 + 2 + 1,
            s = a.util.createBuffer();
          return (
            s.putByte(p.HandshakeType.server_hello),
            s.putInt24(n),
            s.putByte(e.version.major),
            s.putByte(e.version.minor),
            s.putBytes(e.session.sp.server_random),
            l(s, 1, a.util.createBuffer(r)),
            s.putByte(e.session.cipherSuite.id[0]),
            s.putByte(e.session.cipherSuite.id[1]),
            s.putByte(e.session.compressionMethod),
            s
          );
        }),
        (p.createCertificate = function (e) {
          var r,
            n = e.entity === p.ConnectionEnd.client,
            s = null;
          e.getCertificate &&
            ((r = n
              ? e.session.certificateRequest
              : e.session.extensions.server_name.serverNameList),
            (s = e.getCertificate(e, r)));
          var o = a.util.createBuffer();
          if (null !== s)
            try {
              a.util.isArray(s) || (s = [s]);
              for (var c = null, u = 0; u < s.length; ++u) {
                var f = a.pem.decode(s[u])[0];
                if (
                  "CERTIFICATE" !== f.type &&
                  "X509 CERTIFICATE" !== f.type &&
                  "TRUSTED CERTIFICATE" !== f.type
                ) {
                  var h = Error(
                    'Could not convert certificate from PEM; PEM header type is not "CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE".'
                  );
                  throw ((h.headerType = f.type), h);
                }
                if (f.procType && "ENCRYPTED" === f.procType.type)
                  throw Error(
                    "Could not convert certificate from PEM; PEM is encrypted."
                  );
                var d = a.util.createBuffer(f.body);
                null === c && (c = a.asn1.fromDer(d.bytes(), !1));
                var _ = a.util.createBuffer();
                l(_, 3, d), o.putBuffer(_);
              }
              (s = a.pki.certificateFromAsn1(c)),
                n
                  ? (e.session.clientCertificate = s)
                  : (e.session.serverCertificate = s);
            } catch ($) {
              return e.error(e, {
                message: "Could not send certificate list.",
                cause: $,
                send: !0,
                alert: {
                  level: p.Alert.Level.fatal,
                  description: p.Alert.Description.bad_certificate,
                },
              });
            }
          var y = 3 + o.length(),
            g = a.util.createBuffer();
          return (
            g.putByte(p.HandshakeType.certificate), g.putInt24(y), l(g, 3, o), g
          );
        }),
        (p.createClientKeyExchange = function (e) {
          var r = a.util.createBuffer();
          r.putByte(e.session.clientHelloVersion.major),
            r.putByte(e.session.clientHelloVersion.minor),
            r.putBytes(a.random.getBytes(46));
          var n = e.session.sp;
          n.pre_master_secret = r.getBytes();
          var s =
              (r = e.session.serverCertificate.publicKey.encrypt(
                n.pre_master_secret
              )).length + 2,
            o = a.util.createBuffer();
          return (
            o.putByte(p.HandshakeType.client_key_exchange),
            o.putInt24(s),
            o.putInt16(r.length),
            o.putBytes(r),
            o
          );
        }),
        (p.createServerKeyExchange = function (e) {
          return a.util.createBuffer();
        }),
        (p.getClientSignature = function (e, r) {
          var n = a.util.createBuffer();
          n.putBuffer(e.session.md5.digest()),
            n.putBuffer(e.session.sha1.digest()),
            (n = n.getBytes()),
            (e.getSignature =
              e.getSignature ||
              function (e, r, n) {
                var s = null;
                if (e.getPrivateKey)
                  try {
                    (s = e.getPrivateKey(e, e.session.clientCertificate)),
                      (s = a.pki.privateKeyFromPem(s));
                  } catch (o) {
                    e.error(e, {
                      message: "Could not get private key.",
                      cause: o,
                      send: !0,
                      alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.internal_error,
                      },
                    });
                  }
                null === s
                  ? e.error(e, {
                      message: "No private key set.",
                      send: !0,
                      alert: {
                        level: p.Alert.Level.fatal,
                        description: p.Alert.Description.internal_error,
                      },
                    })
                  : (r = s.sign(r, null)),
                  n(e, r);
              }),
            e.getSignature(e, n, r);
        }),
        (p.createCertificateVerify = function (e, r) {
          var n = r.length + 2,
            s = a.util.createBuffer();
          return (
            s.putByte(p.HandshakeType.certificate_verify),
            s.putInt24(n),
            s.putInt16(r.length),
            s.putBytes(r),
            s
          );
        }),
        (p.createCertificateRequest = function (e) {
          var r = a.util.createBuffer();
          r.putByte(1);
          var n = a.util.createBuffer();
          for (var s in e.caStore.certs) {
            var o = e.caStore.certs[s],
              c = a.pki.distinguishedNameToAsn1(o.subject),
              u = a.asn1.toDer(c);
            n.putInt16(u.length()), n.putBuffer(u);
          }
          var f = 1 + r.length() + 2 + n.length(),
            h = a.util.createBuffer();
          return (
            h.putByte(p.HandshakeType.certificate_request),
            h.putInt24(f),
            l(h, 1, r),
            l(h, 2, n),
            h
          );
        }),
        (p.createServerHelloDone = function (e) {
          var r = a.util.createBuffer();
          return r.putByte(p.HandshakeType.server_hello_done), r.putInt24(0), r;
        }),
        (p.createChangeCipherSpec = function () {
          var e = a.util.createBuffer();
          return e.putByte(1), e;
        }),
        (p.createFinished = function (e) {
          var r = a.util.createBuffer();
          r.putBuffer(e.session.md5.digest()),
            r.putBuffer(e.session.sha1.digest());
          var n = e.entity === p.ConnectionEnd.client;
          r = s(
            e.session.sp.master_secret,
            n ? "client finished" : "server finished",
            r.getBytes(),
            12
          );
          var o = a.util.createBuffer();
          return (
            o.putByte(p.HandshakeType.finished),
            o.putInt24(r.length()),
            o.putBuffer(r),
            o
          );
        }),
        (p.createHeartbeat = function (e, r, n) {
          void 0 === n && (n = r.length);
          var s = a.util.createBuffer();
          s.putByte(e), s.putInt16(n), s.putBytes(r);
          var o = Math.max(16, s.length() - n - 3);
          return s.putBytes(a.random.getBytes(o)), s;
        }),
        (p.queue = function (e, r) {
          if (
            r &&
            (0 !== r.fragment.length() ||
              (r.type !== p.ContentType.handshake &&
                r.type !== p.ContentType.alert &&
                r.type !== p.ContentType.change_cipher_spec))
          ) {
            if (r.type === p.ContentType.handshake) {
              var n,
                s = r.fragment.bytes();
              e.session.md5.update(s), e.session.sha1.update(s), (s = null);
            }
            if (r.fragment.length() <= p.MaxFragment) n = [r];
            else {
              n = [];
              for (var o = r.fragment.bytes(); o.length > p.MaxFragment; )
                n.push(
                  p.createRecord(e, {
                    type: r.type,
                    data: a.util.createBuffer(o.slice(0, p.MaxFragment)),
                  })
                ),
                  (o = o.slice(p.MaxFragment));
              o.length > 0 &&
                n.push(
                  p.createRecord(e, {
                    type: r.type,
                    data: a.util.createBuffer(o),
                  })
                );
            }
            for (var c = 0; c < n.length && !e.fail; ++c) {
              var u = n[c];
              e.state.current.write.update(e, u) && e.records.push(u);
            }
          }
        }),
        (p.flush = function (e) {
          for (var r = 0; r < e.records.length; ++r) {
            var n = e.records[r];
            e.tlsData.putByte(n.type),
              e.tlsData.putByte(n.version.major),
              e.tlsData.putByte(n.version.minor),
              e.tlsData.putInt16(n.fragment.length()),
              e.tlsData.putBuffer(e.records[r].fragment);
          }
          return (e.records = []), e.tlsDataReady(e);
        });
      var G = function (e) {
        switch (e) {
          case !0:
            return !0;
          case a.pki.certificateError.bad_certificate:
            return p.Alert.Description.bad_certificate;
          case a.pki.certificateError.unsupported_certificate:
            return p.Alert.Description.unsupported_certificate;
          case a.pki.certificateError.certificate_revoked:
            return p.Alert.Description.certificate_revoked;
          case a.pki.certificateError.certificate_expired:
            return p.Alert.Description.certificate_expired;
          case a.pki.certificateError.certificate_unknown:
            return p.Alert.Description.certificate_unknown;
          case a.pki.certificateError.unknown_ca:
            return p.Alert.Description.unknown_ca;
          default:
            return p.Alert.Description.bad_certificate;
        }
      };
      for (var j in ((p.verifyCertificateChain = function (e, r) {
        try {
          var n = {};
          for (var s in e.verifyOptions) n[s] = e.verifyOptions[s];
          (n.verify = function (r, n, s) {
            G(r);
            var o = e.verify(e, r, n, s);
            if (!0 !== o) {
              if ("object" == typeof o && !a.util.isArray(o)) {
                var c = Error("The application rejected the certificate.");
                throw (
                  ((c.send = !0),
                  (c.alert = {
                    level: p.Alert.Level.fatal,
                    description: p.Alert.Description.bad_certificate,
                  }),
                  o.message && (c.message = o.message),
                  o.alert && (c.alert.description = o.alert),
                  c)
                );
              }
              o !== r &&
                (o = (function (e) {
                  switch (e) {
                    case !0:
                      return !0;
                    case p.Alert.Description.bad_certificate:
                      return a.pki.certificateError.bad_certificate;
                    case p.Alert.Description.unsupported_certificate:
                      return a.pki.certificateError.unsupported_certificate;
                    case p.Alert.Description.certificate_revoked:
                      return a.pki.certificateError.certificate_revoked;
                    case p.Alert.Description.certificate_expired:
                      return a.pki.certificateError.certificate_expired;
                    case p.Alert.Description.certificate_unknown:
                      return a.pki.certificateError.certificate_unknown;
                    case p.Alert.Description.unknown_ca:
                      return a.pki.certificateError.unknown_ca;
                    default:
                      return a.pki.certificateError.bad_certificate;
                  }
                })(o));
            }
            return o;
          }),
            a.pki.verifyCertificateChain(e.caStore, r, n);
        } catch (o) {
          var c = o;
          ("object" != typeof c || a.util.isArray(c)) &&
            (c = {
              send: !0,
              alert: { level: p.Alert.Level.fatal, description: G(o) },
            }),
            "send" in c || (c.send = !0),
            "alert" in c ||
              (c.alert = {
                level: p.Alert.Level.fatal,
                description: G(c.error),
              }),
            e.error(e, c);
        }
        return !e.fail;
      }),
      (p.createSessionCache = function (e, r) {
        var n = null;
        if (e && e.getSession && e.setSession && e.order) n = e;
        else {
          for (var s in (((n = {}).cache = e || {}),
          (n.capacity = Math.max(r || 100, 1)),
          (n.order = []),
          e))
            n.order.length <= r ? n.order.push(s) : delete e[s];
          (n.getSession = function (e) {
            var r = null,
              s = null;
            if (
              (e
                ? (s = a.util.bytesToHex(e))
                : n.order.length > 0 && (s = n.order[0]),
              null !== s && s in n.cache)
            ) {
              for (var o in ((r = n.cache[s]), delete n.cache[s], n.order))
                if (n.order[o] === s) {
                  n.order.splice(o, 1);
                  break;
                }
            }
            return r;
          }),
            (n.setSession = function (e, r) {
              if (n.order.length === n.capacity) {
                var s = n.order.shift();
                delete n.cache[s];
              }
              (s = a.util.bytesToHex(e)), n.order.push(s), (n.cache[s] = r);
            });
        }
        return n;
      }),
      (p.createConnection = function (e) {
        var r = null;
        r = e.caStore
          ? a.util.isArray(e.caStore)
            ? a.pki.createCaStore(e.caStore)
            : e.caStore
          : a.pki.createCaStore();
        var n = e.cipherSuites || null;
        if (null === n)
          for (var s in ((n = []), p.CipherSuites)) n.push(p.CipherSuites[s]);
        var o = e.server ? p.ConnectionEnd.server : p.ConnectionEnd.client,
          c = e.sessionCache ? p.createSessionCache(e.sessionCache) : null,
          u = {
            version: { major: p.Version.major, minor: p.Version.minor },
            entity: o,
            sessionId: e.sessionId,
            caStore: r,
            sessionCache: c,
            cipherSuites: n,
            connected: e.connected,
            virtualHost: e.virtualHost || null,
            verifyClient: e.verifyClient || !1,
            verify:
              e.verify ||
              function (e, r, n, a) {
                return r;
              },
            verifyOptions: e.verifyOptions || {},
            getCertificate: e.getCertificate || null,
            getPrivateKey: e.getPrivateKey || null,
            getSignature: e.getSignature || null,
            input: a.util.createBuffer(),
            tlsData: a.util.createBuffer(),
            data: a.util.createBuffer(),
            tlsDataReady: e.tlsDataReady,
            dataReady: e.dataReady,
            heartbeatReceived: e.heartbeatReceived,
            closed: e.closed,
            error: function (r, n) {
              (n.origin =
                n.origin ||
                (r.entity === p.ConnectionEnd.client ? "client" : "server")),
                n.send && (p.queue(r, p.createAlert(r, n.alert)), p.flush(r));
              var a = !1 !== n.fatal;
              a && (r.fail = !0), e.error(r, n), a && r.close(!1);
            },
            deflate: e.deflate || null,
            inflate: e.inflate || null,
            reset: function (e) {
              (u.version = { major: p.Version.major, minor: p.Version.minor }),
                (u.record = null),
                (u.session = null),
                (u.peerCertificate = null),
                (u.state = { pending: null, current: null }),
                (u.expect = (u.entity, p.ConnectionEnd.client, 0)),
                (u.fragmented = null),
                (u.records = []),
                (u.open = !1),
                (u.handshakes = 0),
                (u.handshaking = !1),
                (u.isConnected = !1),
                (u.fail = !(e || void 0 === e)),
                u.input.clear(),
                u.tlsData.clear(),
                u.data.clear(),
                (u.state.current = p.createConnectionState(u));
            },
          };
        return (
          u.reset(),
          (u.handshake = function (e) {
            if (u.entity !== p.ConnectionEnd.client)
              u.error(u, {
                message: "Cannot initiate handshake as a server.",
                fatal: !1,
              });
            else if (u.handshaking)
              u.error(u, {
                message: "Handshake already in progress.",
                fatal: !1,
              });
            else {
              u.fail && !u.open && 0 === u.handshakes && (u.fail = !1),
                (u.handshaking = !0);
              var r = null;
              (e = e || "").length > 0 &&
                (u.sessionCache && (r = u.sessionCache.getSession(e)),
                null === r && (e = "")),
                0 === e.length &&
                  u.sessionCache &&
                  null !== (r = u.sessionCache.getSession()) &&
                  (e = r.id),
                (u.session = {
                  id: e,
                  version: null,
                  cipherSuite: null,
                  compressionMethod: null,
                  serverCertificate: null,
                  certificateRequest: null,
                  clientCertificate: null,
                  sp: {},
                  md5: a.md.md5.create(),
                  sha1: a.md.sha1.create(),
                }),
                r && ((u.version = r.version), (u.session.sp = r.sp)),
                (u.session.sp.client_random = p.createRandom().getBytes()),
                (u.open = !0),
                p.queue(
                  u,
                  p.createRecord(u, {
                    type: p.ContentType.handshake,
                    data: p.createClientHello(u),
                  })
                ),
                p.flush(u);
            }
          }),
          (u.process = function (e) {
            var r,
              n,
              s,
              o,
              c,
              l,
              f,
              h,
              d = 0;
            return (
              e && u.input.putBytes(e),
              u.fail ||
                (null !== u.record &&
                  u.record.ready &&
                  u.record.fragment.isEmpty() &&
                  (u.record = null),
                null === u.record &&
                  (d = (function (e) {
                    var r = 0,
                      n = e.input,
                      s = n.length();
                    if (s < 5) r = 5 - s;
                    else {
                      e.record = {
                        type: n.getByte(),
                        version: { major: n.getByte(), minor: n.getByte() },
                        length: n.getInt16(),
                        fragment: a.util.createBuffer(),
                        ready: !1,
                      };
                      var o = e.record.version.major === e.version.major;
                      o &&
                        e.session &&
                        e.session.version &&
                        (o = e.record.version.minor === e.version.minor),
                        o ||
                          e.error(e, {
                            message: "Incompatible TLS version.",
                            send: !0,
                            alert: {
                              level: p.Alert.Level.fatal,
                              description: p.Alert.Description.protocol_version,
                            },
                          });
                    }
                    return r;
                  })(u)),
                u.fail ||
                  null === u.record ||
                  u.record.ready ||
                  (d =
                    ((n = 0),
                    (o = (s = (r = u).input).length()) < r.record.length
                      ? (n = r.record.length - o)
                      : (r.record.fragment.putBytes(
                          s.getBytes(r.record.length)
                        ),
                        s.compact(),
                        r.state.current.read.update(r, r.record) &&
                          (null !== r.fragmented &&
                            (r.fragmented.type === r.record.type
                              ? (r.fragmented.fragment.putBuffer(
                                  r.record.fragment
                                ),
                                (r.record = r.fragmented))
                              : r.error(r, {
                                  message: "Invalid fragmented record.",
                                  send: !0,
                                  alert: {
                                    level: p.Alert.Level.fatal,
                                    description:
                                      p.Alert.Description.unexpected_message,
                                  },
                                })),
                          (r.record.ready = !0))),
                    n)),
                !u.fail &&
                  null !== u.record &&
                  u.record.ready &&
                  ((c = u),
                  (f =
                    (l = u.record).type - p.ContentType.change_cipher_spec) in
                  (h = L[c.entity][c.expect])
                    ? h[f](c, l)
                    : p.handleUnexpected(c, l))),
              d
            );
          }),
          (u.prepare = function (e) {
            return (
              p.queue(
                u,
                p.createRecord(u, {
                  type: p.ContentType.application_data,
                  data: a.util.createBuffer(e),
                })
              ),
              p.flush(u)
            );
          }),
          (u.prepareHeartbeatRequest = function (e, r) {
            return (
              e instanceof a.util.ByteBuffer && (e = e.bytes()),
              void 0 === r && (r = e.length),
              (u.expectedHeartbeatPayload = e),
              p.queue(
                u,
                p.createRecord(u, {
                  type: p.ContentType.heartbeat,
                  data: p.createHeartbeat(
                    p.HeartbeatMessageType.heartbeat_request,
                    e,
                    r
                  ),
                })
              ),
              p.flush(u)
            );
          }),
          (u.close = function (e) {
            if (!u.fail && u.sessionCache && u.session) {
              var r = {
                id: u.session.id,
                version: u.session.version,
                sp: u.session.sp,
              };
              (r.sp.keys = null), u.sessionCache.setSession(r.id, r);
            }
            u.open &&
              ((u.open = !1),
              u.input.clear(),
              (u.isConnected || u.handshaking) &&
                ((u.isConnected = u.handshaking = !1),
                p.queue(
                  u,
                  p.createAlert(u, {
                    level: p.Alert.Level.warning,
                    description: p.Alert.Description.close_notify,
                  })
                ),
                p.flush(u)),
              u.closed(u)),
              u.reset(e);
          }),
          u
        );
      }),
      (e.exports = a.tls = a.tls || {}),
      p))
        "function" != typeof p[j] && (a.tls[j] = p[j]);
      (a.tls.prf_tls1 = s),
        (a.tls.hmac_sha1 = function (e, r, n) {
          var s = a.hmac.create();
          s.start("SHA1", e);
          var o = a.util.createBuffer();
          return (
            o.putInt32(r[0]),
            o.putInt32(r[1]),
            o.putByte(n.type),
            o.putByte(n.version.major),
            o.putByte(n.version.minor),
            o.putInt16(n.length),
            o.putBytes(n.fragment.bytes()),
            s.update(o.getBytes()),
            s.digest().getBytes()
          );
        }),
        (a.tls.createSessionCache = p.createSessionCache),
        (a.tls.createConnection = p.createConnection);
    },
    function (e, r, n) {
      var a = n(0);
      n(3), n(6), n(22), n(7), n(15), n(28), n(18), n(11), n(1), n(17);
      var s = a.asn1,
        o = (e.exports = a.pki = a.pki || {});
      (o.pemToDer = function (e) {
        var r = a.pem.decode(e)[0];
        if (r.procType && "ENCRYPTED" === r.procType.type)
          throw Error("Could not convert PEM to DER; PEM is encrypted.");
        return a.util.createBuffer(r.body);
      }),
        (o.privateKeyFromPem = function (e) {
          var r = a.pem.decode(e)[0];
          if ("PRIVATE KEY" !== r.type && "RSA PRIVATE KEY" !== r.type) {
            var n = Error(
              'Could not convert private key from PEM; PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".'
            );
            throw ((n.headerType = r.type), n);
          }
          if (r.procType && "ENCRYPTED" === r.procType.type)
            throw Error(
              "Could not convert private key from PEM; PEM is encrypted."
            );
          var c = s.fromDer(r.body);
          return o.privateKeyFromAsn1(c);
        }),
        (o.privateKeyToPem = function (e, r) {
          var n = {
            type: "RSA PRIVATE KEY",
            body: s.toDer(o.privateKeyToAsn1(e)).getBytes(),
          };
          return a.pem.encode(n, { maxline: r });
        }),
        (o.privateKeyInfoToPem = function (e, r) {
          var n = { type: "PRIVATE KEY", body: s.toDer(e).getBytes() };
          return a.pem.encode(n, { maxline: r });
        });
    },
    function (e, r, n) {
      var a = n(0);
      if (
        (n(5),
        n(3),
        n(10),
        n(4),
        n(6),
        n(15),
        n(7),
        n(2),
        n(25),
        n(11),
        n(1),
        void 0 === s)
      )
        var s = a.jsbn.BigInteger;
      var o = a.asn1,
        c = (a.pki = a.pki || {});
      e.exports = c.pbe = a.pbe = a.pbe || {};
      var u = c.oids,
        l = {
          name: "EncryptedPrivateKeyInfo",
          tagClass: o.Class.UNIVERSAL,
          type: o.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "EncryptedPrivateKeyInfo.encryptionAlgorithm",
              tagClass: o.Class.UNIVERSAL,
              type: o.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "AlgorithmIdentifier.algorithm",
                  tagClass: o.Class.UNIVERSAL,
                  type: o.Type.OID,
                  constructed: !1,
                  capture: "encryptionOid",
                },
                {
                  name: "AlgorithmIdentifier.parameters",
                  tagClass: o.Class.UNIVERSAL,
                  type: o.Type.SEQUENCE,
                  constructed: !0,
                  captureAsn1: "encryptionParams",
                },
              ],
            },
            {
              name: "EncryptedPrivateKeyInfo.encryptedData",
              tagClass: o.Class.UNIVERSAL,
              type: o.Type.OCTETSTRING,
              constructed: !1,
              capture: "encryptedData",
            },
          ],
        },
        p = {
          name: "PBES2Algorithms",
          tagClass: o.Class.UNIVERSAL,
          type: o.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "PBES2Algorithms.keyDerivationFunc",
              tagClass: o.Class.UNIVERSAL,
              type: o.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "PBES2Algorithms.keyDerivationFunc.oid",
                  tagClass: o.Class.UNIVERSAL,
                  type: o.Type.OID,
                  constructed: !1,
                  capture: "kdfOid",
                },
                {
                  name: "PBES2Algorithms.params",
                  tagClass: o.Class.UNIVERSAL,
                  type: o.Type.SEQUENCE,
                  constructed: !0,
                  value: [
                    {
                      name: "PBES2Algorithms.params.salt",
                      tagClass: o.Class.UNIVERSAL,
                      type: o.Type.OCTETSTRING,
                      constructed: !1,
                      capture: "kdfSalt",
                    },
                    {
                      name: "PBES2Algorithms.params.iterationCount",
                      tagClass: o.Class.UNIVERSAL,
                      type: o.Type.INTEGER,
                      constructed: !1,
                      capture: "kdfIterationCount",
                    },
                    {
                      name: "PBES2Algorithms.params.keyLength",
                      tagClass: o.Class.UNIVERSAL,
                      type: o.Type.INTEGER,
                      constructed: !1,
                      optional: !0,
                      capture: "keyLength",
                    },
                    {
                      name: "PBES2Algorithms.params.prf",
                      tagClass: o.Class.UNIVERSAL,
                      type: o.Type.SEQUENCE,
                      constructed: !0,
                      optional: !0,
                      value: [
                        {
                          name: "PBES2Algorithms.params.prf.algorithm",
                          tagClass: o.Class.UNIVERSAL,
                          type: o.Type.OID,
                          constructed: !1,
                          capture: "prfOid",
                        },
                      ],
                    },
                  ],
                },
              ],
            },
            {
              name: "PBES2Algorithms.encryptionScheme",
              tagClass: o.Class.UNIVERSAL,
              type: o.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "PBES2Algorithms.encryptionScheme.oid",
                  tagClass: o.Class.UNIVERSAL,
                  type: o.Type.OID,
                  constructed: !1,
                  capture: "encOid",
                },
                {
                  name: "PBES2Algorithms.encryptionScheme.iv",
                  tagClass: o.Class.UNIVERSAL,
                  type: o.Type.OCTETSTRING,
                  constructed: !1,
                  capture: "encIv",
                },
              ],
            },
          ],
        },
        f = {
          name: "pkcs-12PbeParams",
          tagClass: o.Class.UNIVERSAL,
          type: o.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "pkcs-12PbeParams.salt",
              tagClass: o.Class.UNIVERSAL,
              type: o.Type.OCTETSTRING,
              constructed: !1,
              capture: "salt",
            },
            {
              name: "pkcs-12PbeParams.iterations",
              tagClass: o.Class.UNIVERSAL,
              type: o.Type.INTEGER,
              constructed: !1,
              capture: "iterations",
            },
          ],
        };
      function h(e, r) {
        return e.start().update(r).digest().getBytes();
      }
      function d(e) {
        var r;
        if (e) {
          if (!(r = c.oids[o.derToOid(e)])) {
            var n = Error("Unsupported PRF OID.");
            throw (
              ((n.oid = e),
              (n.supported = [
                "hmacWithSHA1",
                "hmacWithSHA224",
                "hmacWithSHA256",
                "hmacWithSHA384",
                "hmacWithSHA512",
              ]),
              n)
            );
          }
        } else r = "hmacWithSHA1";
        return _(r);
      }
      function _(e) {
        var r = a.md;
        switch (e) {
          case "hmacWithSHA224":
            r = a.md.sha512;
          case "hmacWithSHA1":
          case "hmacWithSHA256":
          case "hmacWithSHA384":
          case "hmacWithSHA512":
            e = e.substr(8).toLowerCase();
            break;
          default:
            var n = Error("Unsupported PRF algorithm.");
            throw (
              ((n.algorithm = e),
              (n.supported = [
                "hmacWithSHA1",
                "hmacWithSHA224",
                "hmacWithSHA256",
                "hmacWithSHA384",
                "hmacWithSHA512",
              ]),
              n)
            );
        }
        if (!r || !(e in r)) throw Error("Unknown hash algorithm: " + e);
        return r[e].create();
      }
      (c.encryptPrivateKeyInfo = function (e, r, n) {
        ((n = n || {}).saltSize = n.saltSize || 8),
          (n.count = n.count || 2048),
          (n.algorithm = n.algorithm || "aes128"),
          (n.prfAlgorithm = n.prfAlgorithm || "sha1");
        var s,
          l,
          p,
          f = a.random.getBytesSync(n.saltSize),
          h = n.count,
          d = o.integerToDer(h);
        if (0 === n.algorithm.indexOf("aes") || "des" === n.algorithm) {
          switch (n.algorithm) {
            case "aes128":
              (s = 16),
                ($ = 16),
                (y = u["aes128-CBC"]),
                (g = a.aes.createEncryptionCipher);
              break;
            case "aes192":
              (s = 24),
                ($ = 16),
                (y = u["aes192-CBC"]),
                (g = a.aes.createEncryptionCipher);
              break;
            case "aes256":
              (s = 32),
                ($ = 16),
                (y = u["aes256-CBC"]),
                (g = a.aes.createEncryptionCipher);
              break;
            case "des":
              (s = 8),
                ($ = 8),
                (y = u.desCBC),
                (g = a.des.createEncryptionCipher);
              break;
            default:
              throw (
                (((N = Error(
                  "Cannot encrypt private key. Unknown encryption algorithm."
                )).algorithm = n.algorithm),
                N)
              );
          }
          var $,
            y,
            g,
            v,
            m,
            C,
            E,
            S,
            T = "hmacWith" + n.prfAlgorithm.toUpperCase(),
            B = _(T),
            I = a.pkcs5.pbkdf2(r, f, h, s, B),
            A = a.random.getBytesSync($);
          (R = g(I)).start(A),
            R.update(o.toDer(e)),
            R.finish(),
            (p = R.output.getBytes());
          var b =
            ((v = f),
            (m = d),
            (C = s),
            (E = T),
            (S = o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
              o.create(o.Class.UNIVERSAL, o.Type.OCTETSTRING, !1, v),
              o.create(o.Class.UNIVERSAL, o.Type.INTEGER, !1, m.getBytes()),
            ])),
            "hmacWithSHA1" !== E &&
              S.value.push(
                o.create(
                  o.Class.UNIVERSAL,
                  o.Type.INTEGER,
                  !1,
                  a.util.hexToBytes(C.toString(16))
                ),
                o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
                  o.create(
                    o.Class.UNIVERSAL,
                    o.Type.OID,
                    !1,
                    o.oidToDer(c.oids[E]).getBytes()
                  ),
                  o.create(o.Class.UNIVERSAL, o.Type.NULL, !1, ""),
                ])
              ),
            S);
          l = o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
            o.create(
              o.Class.UNIVERSAL,
              o.Type.OID,
              !1,
              o.oidToDer(u.pkcs5PBES2).getBytes()
            ),
            o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
              o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
                o.create(
                  o.Class.UNIVERSAL,
                  o.Type.OID,
                  !1,
                  o.oidToDer(u.pkcs5PBKDF2).getBytes()
                ),
                b,
              ]),
              o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
                o.create(
                  o.Class.UNIVERSAL,
                  o.Type.OID,
                  !1,
                  o.oidToDer(y).getBytes()
                ),
                o.create(o.Class.UNIVERSAL, o.Type.OCTETSTRING, !1, A),
              ]),
            ]),
          ]);
        } else {
          if ("3des" !== n.algorithm)
            throw (
              (((N = Error(
                "Cannot encrypt private key. Unknown encryption algorithm."
              )).algorithm = n.algorithm),
              N)
            );
          s = 24;
          var N,
            R,
            k = new a.util.ByteBuffer(f);
          (I = c.pbe.generatePkcs12Key(r, k, 1, h, s)),
            (A = c.pbe.generatePkcs12Key(r, k, 2, h, s)),
            (R = a.des.createEncryptionCipher(I)).start(A),
            R.update(o.toDer(e)),
            R.finish(),
            (p = R.output.getBytes()),
            (l = o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
              o.create(
                o.Class.UNIVERSAL,
                o.Type.OID,
                !1,
                o.oidToDer(u["pbeWithSHAAnd3-KeyTripleDES-CBC"]).getBytes()
              ),
              o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
                o.create(o.Class.UNIVERSAL, o.Type.OCTETSTRING, !1, f),
                o.create(o.Class.UNIVERSAL, o.Type.INTEGER, !1, d.getBytes()),
              ]),
            ]));
        }
        return o.create(o.Class.UNIVERSAL, o.Type.SEQUENCE, !0, [
          l,
          o.create(o.Class.UNIVERSAL, o.Type.OCTETSTRING, !1, p),
        ]);
      }),
        (c.decryptPrivateKeyInfo = function (e, r) {
          var n = null,
            s = {},
            u = [];
          if (!o.validate(e, l, s, u)) {
            var p = Error(
              "Cannot read encrypted private key. ASN.1 object is not a supported EncryptedPrivateKeyInfo."
            );
            throw ((p.errors = u), p);
          }
          var f = o.derToOid(s.encryptionOid),
            h = c.pbe.getCipher(f, s.encryptionParams, r),
            d = a.util.createBuffer(s.encryptedData);
          return h.update(d), h.finish() && (n = o.fromDer(h.output)), n;
        }),
        (c.encryptedPrivateKeyToPem = function (e, r) {
          var n = {
            type: "ENCRYPTED PRIVATE KEY",
            body: o.toDer(e).getBytes(),
          };
          return a.pem.encode(n, { maxline: r });
        }),
        (c.encryptedPrivateKeyFromPem = function (e) {
          var r = a.pem.decode(e)[0];
          if ("ENCRYPTED PRIVATE KEY" !== r.type) {
            var n = Error(
              'Could not convert encrypted private key from PEM; PEM header type is "ENCRYPTED PRIVATE KEY".'
            );
            throw ((n.headerType = r.type), n);
          }
          if (r.procType && "ENCRYPTED" === r.procType.type)
            throw Error(
              "Could not convert encrypted private key from PEM; PEM is encrypted."
            );
          return o.fromDer(r.body);
        }),
        (c.encryptRsaPrivateKey = function (e, r, n) {
          if (!(n = n || {}).legacy) {
            var s,
              u,
              l,
              p,
              f = c.wrapRsaPrivateKey(c.privateKeyToAsn1(e));
            return (
              (f = c.encryptPrivateKeyInfo(f, r, n)),
              c.encryptedPrivateKeyToPem(f)
            );
          }
          switch (n.algorithm) {
            case "aes128":
              (s = "AES-128-CBC"),
                (l = 16),
                (u = a.random.getBytesSync(16)),
                (p = a.aes.createEncryptionCipher);
              break;
            case "aes192":
              (s = "AES-192-CBC"),
                (l = 24),
                (u = a.random.getBytesSync(16)),
                (p = a.aes.createEncryptionCipher);
              break;
            case "aes256":
              (s = "AES-256-CBC"),
                (l = 32),
                (u = a.random.getBytesSync(16)),
                (p = a.aes.createEncryptionCipher);
              break;
            case "3des":
              (s = "DES-EDE3-CBC"),
                (l = 24),
                (u = a.random.getBytesSync(8)),
                (p = a.des.createEncryptionCipher);
              break;
            case "des":
              (s = "DES-CBC"),
                (l = 8),
                (u = a.random.getBytesSync(8)),
                (p = a.des.createEncryptionCipher);
              break;
            default:
              var h = Error(
                'Could not encrypt RSA private key; unsupported encryption algorithm "' +
                  n.algorithm +
                  '".'
              );
              throw ((h.algorithm = n.algorithm), h);
          }
          var d = p(a.pbe.opensslDeriveBytes(r, u.substr(0, 8), l));
          d.start(u), d.update(o.toDer(c.privateKeyToAsn1(e))), d.finish();
          var _ = {
            type: "RSA PRIVATE KEY",
            procType: { version: "4", type: "ENCRYPTED" },
            dekInfo: {
              algorithm: s,
              parameters: a.util.bytesToHex(u).toUpperCase(),
            },
            body: d.output.getBytes(),
          };
          return a.pem.encode(_);
        }),
        (c.decryptRsaPrivateKey = function (e, r) {
          var n = null,
            s = a.pem.decode(e)[0];
          if (
            "ENCRYPTED PRIVATE KEY" !== s.type &&
            "PRIVATE KEY" !== s.type &&
            "RSA PRIVATE KEY" !== s.type
          )
            throw (
              (((p = Error(
                'Could not convert private key from PEM; PEM header type is not "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", or "RSA PRIVATE KEY".'
              )).headerType = p),
              p)
            );
          if (s.procType && "ENCRYPTED" === s.procType.type) {
            switch (s.dekInfo.algorithm) {
              case "DES-CBC":
                (u = 8), (l = a.des.createDecryptionCipher);
                break;
              case "DES-EDE3-CBC":
                (u = 24), (l = a.des.createDecryptionCipher);
                break;
              case "AES-128-CBC":
                (u = 16), (l = a.aes.createDecryptionCipher);
                break;
              case "AES-192-CBC":
                (u = 24), (l = a.aes.createDecryptionCipher);
                break;
              case "AES-256-CBC":
                (u = 32), (l = a.aes.createDecryptionCipher);
                break;
              case "RC2-40-CBC":
                (u = 5),
                  (l = function (e) {
                    return a.rc2.createDecryptionCipher(e, 40);
                  });
                break;
              case "RC2-64-CBC":
                (u = 8),
                  (l = function (e) {
                    return a.rc2.createDecryptionCipher(e, 64);
                  });
                break;
              case "RC2-128-CBC":
                (u = 16),
                  (l = function (e) {
                    return a.rc2.createDecryptionCipher(e, 128);
                  });
                break;
              default:
                throw (
                  (((p = Error(
                    'Could not decrypt private key; unsupported encryption algorithm "' +
                      s.dekInfo.algorithm +
                      '".'
                  )).algorithm = s.dekInfo.algorithm),
                  p)
                );
            }
            var u,
              l,
              p,
              f = a.util.hexToBytes(s.dekInfo.parameters),
              h = l(a.pbe.opensslDeriveBytes(r, f.substr(0, 8), u));
            if (
              (h.start(f), h.update(a.util.createBuffer(s.body)), !h.finish())
            )
              return n;
            n = h.output.getBytes();
          } else n = s.body;
          return (
            null !==
              (n =
                "ENCRYPTED PRIVATE KEY" === s.type
                  ? c.decryptPrivateKeyInfo(o.fromDer(n), r)
                  : o.fromDer(n)) && (n = c.privateKeyFromAsn1(n)),
            n
          );
        }),
        (c.pbe.generatePkcs12Key = function (e, r, n, s, o, c) {
          if (null == c) {
            if (!("sha1" in a.md))
              throw Error('"sha1" hash algorithm unavailable.');
            c = a.md.sha1.create();
          }
          var u,
            l,
            p = c.digestLength,
            f = c.blockLength,
            h = new a.util.ByteBuffer(),
            d = new a.util.ByteBuffer();
          if (null != e) {
            for (l = 0; l < e.length; l++) d.putInt16(e.charCodeAt(l));
            d.putInt16(0);
          }
          var _ = d.length(),
            $ = r.length(),
            y = new a.util.ByteBuffer();
          y.fillWithByte(n, f);
          var g = f * Math.ceil($ / f),
            v = new a.util.ByteBuffer();
          for (l = 0; l < g; l++) v.putByte(r.at(l % $));
          var m = f * Math.ceil(_ / f),
            C = new a.util.ByteBuffer();
          for (l = 0; l < m; l++) C.putByte(d.at(l % _));
          var E = v;
          E.putBuffer(C);
          for (var S = Math.ceil(o / p), T = 1; T <= S; T++) {
            var B = new a.util.ByteBuffer();
            B.putBytes(y.bytes()), B.putBytes(E.bytes());
            for (var I = 0; I < s; I++)
              c.start(), c.update(B.getBytes()), (B = c.digest());
            var A = new a.util.ByteBuffer();
            for (l = 0; l < f; l++) A.putByte(B.at(l % p));
            var b = Math.ceil($ / f) + Math.ceil(_ / f),
              N = new a.util.ByteBuffer();
            for (u = 0; u < b; u++) {
              var R = new a.util.ByteBuffer(E.getBytes(f)),
                k = 511;
              for (l = A.length() - 1; l >= 0; l--)
                (k >>= 8), (k += A.at(l) + R.at(l)), R.setAt(l, 255 & k);
              N.putBuffer(R);
            }
            (E = N), h.putBuffer(B);
          }
          return h.truncate(h.length() - o), h;
        }),
        (c.pbe.getCipher = function (e, r, n) {
          switch (e) {
            case c.oids.pkcs5PBES2:
              return c.pbe.getCipherForPBES2(e, r, n);
            case c.oids["pbeWithSHAAnd3-KeyTripleDES-CBC"]:
            case c.oids["pbewithSHAAnd40BitRC2-CBC"]:
              return c.pbe.getCipherForPKCS12PBE(e, r, n);
            default:
              var a = Error(
                "Cannot read encrypted PBE data block. Unsupported OID."
              );
              throw (
                ((a.oid = e),
                (a.supportedOids = [
                  "pkcs5PBES2",
                  "pbeWithSHAAnd3-KeyTripleDES-CBC",
                  "pbewithSHAAnd40BitRC2-CBC",
                ]),
                a)
              );
          }
        }),
        (c.pbe.getCipherForPBES2 = function (e, r, n) {
          var s,
            u = {},
            l = [];
          if (!o.validate(r, p, u, l))
            throw (
              (((s = Error(
                "Cannot read password-based-encryption algorithm parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo."
              )).errors = l),
              s)
            );
          if ((e = o.derToOid(u.kdfOid)) !== c.oids.pkcs5PBKDF2)
            throw (
              (((s = Error(
                "Cannot read encrypted private key. Unsupported key derivation function OID."
              )).oid = e),
              (s.supportedOids = ["pkcs5PBKDF2"]),
              s)
            );
          if (
            (e = o.derToOid(u.encOid)) !== c.oids["aes128-CBC"] &&
            e !== c.oids["aes192-CBC"] &&
            e !== c.oids["aes256-CBC"] &&
            e !== c.oids["des-EDE3-CBC"] &&
            e !== c.oids.desCBC
          )
            throw (
              (((s = Error(
                "Cannot read encrypted private key. Unsupported encryption scheme OID."
              )).oid = e),
              (s.supportedOids = [
                "aes128-CBC",
                "aes192-CBC",
                "aes256-CBC",
                "des-EDE3-CBC",
                "desCBC",
              ]),
              s)
            );
          var f,
            h,
            _ = u.kdfSalt,
            $ = a.util.createBuffer(u.kdfIterationCount);
          switch ((($ = $.getInt($.length() << 3)), c.oids[e])) {
            case "aes128-CBC":
              (f = 16), (h = a.aes.createDecryptionCipher);
              break;
            case "aes192-CBC":
              (f = 24), (h = a.aes.createDecryptionCipher);
              break;
            case "aes256-CBC":
              (f = 32), (h = a.aes.createDecryptionCipher);
              break;
            case "des-EDE3-CBC":
              (f = 24), (h = a.des.createDecryptionCipher);
              break;
            case "desCBC":
              (f = 8), (h = a.des.createDecryptionCipher);
          }
          var y = d(u.prfOid),
            g = a.pkcs5.pbkdf2(n, _, $, f, y),
            v = u.encIv,
            m = h(g);
          return m.start(v), m;
        }),
        (c.pbe.getCipherForPKCS12PBE = function (e, r, n) {
          var s,
            u = {},
            l = [];
          if (!o.validate(r, f, u, l))
            throw (
              (((s = Error(
                "Cannot read password-based-encryption algorithm parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo."
              )).errors = l),
              s)
            );
          var p,
            h,
            _,
            $ = a.util.createBuffer(u.salt),
            y = a.util.createBuffer(u.iterations);
          switch (((y = y.getInt(y.length() << 3)), e)) {
            case c.oids["pbeWithSHAAnd3-KeyTripleDES-CBC"]:
              (p = 24), (h = 8), (_ = a.des.startDecrypting);
              break;
            case c.oids["pbewithSHAAnd40BitRC2-CBC"]:
              (p = 5),
                (h = 8),
                (_ = function (e, r) {
                  var n = a.rc2.createDecryptionCipher(e, 40);
                  return n.start(r, null), n;
                });
              break;
            default:
              throw (
                (((s = Error(
                  "Cannot read PKCS #12 PBE data block. Unsupported OID."
                )).oid = e),
                s)
              );
          }
          var g = d(u.prfOid),
            v = c.pbe.generatePkcs12Key(n, $, 1, y, p, g);
          return g.start(), _(v, c.pbe.generatePkcs12Key(n, $, 2, y, h, g));
        }),
        (c.pbe.opensslDeriveBytes = function (e, r, n, s) {
          if (null == s) {
            if (!("md5" in a.md))
              throw Error('"md5" hash algorithm unavailable.');
            s = a.md.md5.create();
          }
          null === r && (r = "");
          for (var o = [h(s, e + r)], c = 16, u = 1; c < n; ++u, c += 16)
            o.push(h(s, o[u - 1] + e + r));
          return o.join("").substr(0, n);
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(4), n(1);
      var s = (e.exports = a.sha256 = a.sha256 || {});
      (a.md.sha256 = a.md.algorithms.sha256 = s),
        (s.create = function () {
          c ||
            ((o = "\x80"),
            (o += a.util.fillString("\0", 64)),
            (u = [
              1116352408, 1899447441, 3049323471, 3921009573, 961987163,
              1508970993, 2453635748, 2870763221, 3624381080, 310598401,
              607225278, 1426881987, 1925078388, 2162078206, 2614888103,
              3248222580, 3835390401, 4022224774, 264347078, 604807628,
              770255983, 1249150122, 1555081692, 1996064986, 2554220882,
              2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
              113926993, 338241895, 666307205, 773529912, 1294757372,
              1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
              2730485921, 2820302411, 3259730800, 3345764771, 3516065817,
              3600352804, 4094571909, 275423344, 430227734, 506948616,
              659060556, 883997877, 958139571, 1322822218, 1537002063,
              1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
              2428436474, 2756734187, 3204031479, 3329325298,
            ]),
            (c = !0));
          var e = null,
            r = a.util.createBuffer(),
            n = Array(64),
            s = {
              algorithm: "sha256",
              blockLength: 64,
              digestLength: 32,
              messageLength: 0,
              fullMessageLength: null,
              messageLengthSize: 8,
              start: function () {
                (s.messageLength = 0),
                  (s.fullMessageLength = s.messageLength64 = []);
                for (var n = s.messageLengthSize / 4, o = 0; o < n; ++o)
                  s.fullMessageLength.push(0);
                return (
                  (r = a.util.createBuffer()),
                  (e = {
                    h0: 1779033703,
                    h1: 3144134277,
                    h2: 1013904242,
                    h3: 2773480762,
                    h4: 1359893119,
                    h5: 2600822924,
                    h6: 528734635,
                    h7: 1541459225,
                  }),
                  s
                );
              },
            };
          return (
            s.start(),
            (s.update = function (o, c) {
              "utf8" === c && (o = a.util.encodeUtf8(o));
              var u = o.length;
              (s.messageLength += u), (u = [(u / 4294967296) >>> 0, u >>> 0]);
              for (var p = s.fullMessageLength.length - 1; p >= 0; --p)
                (s.fullMessageLength[p] += u[1]),
                  (u[1] = u[0] + ((s.fullMessageLength[p] / 4294967296) >>> 0)),
                  (s.fullMessageLength[p] = s.fullMessageLength[p] >>> 0),
                  (u[0] = (u[1] / 4294967296) >>> 0);
              return (
                r.putBytes(o),
                l(e, n, r),
                (r.read > 2048 || 0 === r.length()) && r.compact(),
                s
              );
            }),
            (s.digest = function () {
              var c = a.util.createBuffer();
              c.putBytes(r.bytes());
              var u,
                p =
                  (s.fullMessageLength[s.fullMessageLength.length - 1] +
                    s.messageLengthSize) &
                  (s.blockLength - 1);
              c.putBytes(o.substr(0, s.blockLength - p));
              for (
                var f = 8 * s.fullMessageLength[0], h = 0;
                h < s.fullMessageLength.length - 1;
                ++h
              )
                (f +=
                  ((u = 8 * s.fullMessageLength[h + 1]) / 4294967296) >>> 0),
                  c.putInt32(f >>> 0),
                  (f = u >>> 0);
              c.putInt32(f);
              var d = {
                h0: e.h0,
                h1: e.h1,
                h2: e.h2,
                h3: e.h3,
                h4: e.h4,
                h5: e.h5,
                h6: e.h6,
                h7: e.h7,
              };
              l(d, n, c);
              var _ = a.util.createBuffer();
              return (
                _.putInt32(d.h0),
                _.putInt32(d.h1),
                _.putInt32(d.h2),
                _.putInt32(d.h3),
                _.putInt32(d.h4),
                _.putInt32(d.h5),
                _.putInt32(d.h6),
                _.putInt32(d.h7),
                _
              );
            }),
            s
          );
        });
      var o = null,
        c = !1,
        u = null;
      function l(e, r, n) {
        for (
          var a, s, o, c, l, p, f, h, d, _, $, y, g, v = n.length();
          v >= 64;

        ) {
          for (l = 0; l < 16; ++l) r[l] = n.getInt32();
          for (; l < 64; ++l)
            (a =
              (((a = r[l - 2]) >>> 17) | (a << 15)) ^
              ((a >>> 19) | (a << 13)) ^
              (a >>> 10)),
              (s =
                (((s = r[l - 15]) >>> 7) | (s << 25)) ^
                ((s >>> 18) | (s << 14)) ^
                (s >>> 3)),
              (r[l] = (a + r[l - 7] + s + r[l - 16]) | 0);
          for (
            p = e.h0,
              f = e.h1,
              h = e.h2,
              d = e.h3,
              _ = e.h4,
              $ = e.h5,
              y = e.h6,
              g = e.h7,
              l = 0;
            l < 64;
            ++l
          )
            (o =
              ((p >>> 2) | (p << 30)) ^
              ((p >>> 13) | (p << 19)) ^
              ((p >>> 22) | (p << 10))),
              (c = (p & f) | (h & (p ^ f))),
              (a =
                g +
                (((_ >>> 6) | (_ << 26)) ^
                  ((_ >>> 11) | (_ << 21)) ^
                  ((_ >>> 25) | (_ << 7))) +
                (y ^ (_ & ($ ^ y))) +
                u[l] +
                r[l]),
              (g = y),
              (y = $),
              ($ = _),
              (_ = (d + a) >>> 0),
              (d = h),
              (h = f),
              (f = p),
              (p = (a + (s = o + c)) >>> 0);
          (e.h0 = (e.h0 + p) | 0),
            (e.h1 = (e.h1 + f) | 0),
            (e.h2 = (e.h2 + h) | 0),
            (e.h3 = (e.h3 + d) | 0),
            (e.h4 = (e.h4 + _) | 0),
            (e.h5 = (e.h5 + $) | 0),
            (e.h6 = (e.h6 + y) | 0),
            (e.h7 = (e.h7 + g) | 0),
            (v -= 64);
        }
      }
    },
    function (e, r, n) {
      var a = n(0);
      n(1);
      var s = null;
      !a.util.isNodejs ||
        a.options.usePureJavaScript ||
        process.versions["node-webkit"] ||
        (s = n(16)),
        ((e.exports = a.prng = a.prng || {}).create = function (e) {
          for (
            var r = {
                plugin: e,
                key: null,
                seed: null,
                time: null,
                reseeds: 0,
                generated: 0,
                keyBytes: "",
              },
              n = e.md,
              o = Array(32),
              c = 0;
            c < 32;
            ++c
          )
            o[c] = n.create();
          function u() {
            if (r.pools[0].messageLength >= 32) return l();
            var e = (32 - r.pools[0].messageLength) << 5;
            r.collect(r.seedFileSync(e)), l();
          }
          function l() {
            r.reseeds = 4294967295 === r.reseeds ? 0 : r.reseeds + 1;
            var e = r.plugin.md.create();
            e.update(r.keyBytes);
            for (var n = 1, a = 0; a < 32; ++a)
              r.reseeds % n == 0 &&
                (e.update(r.pools[a].digest().getBytes()), r.pools[a].start()),
                (n <<= 1);
            (r.keyBytes = e.digest().getBytes()),
              e.start(),
              e.update(r.keyBytes);
            var s = e.digest().getBytes();
            (r.key = r.plugin.formatKey(r.keyBytes)),
              (r.seed = r.plugin.formatSeed(s)),
              (r.generated = 0);
          }
          function p(e) {
            var r = null,
              n = a.util.globalScope,
              s = n.crypto || n.msCrypto;
            s &&
              s.getRandomValues &&
              (r = function (e) {
                return s.getRandomValues(e);
              });
            var o = a.util.createBuffer();
            if (r)
              for (; o.length() < e; ) {
                var c = Math.max(1, Math.min(e - o.length(), 65536) / 4),
                  u = new Uint32Array(Math.floor(c));
                try {
                  r(u);
                  for (var l = 0; l < u.length; ++l) o.putInt32(u[l]);
                } catch (p) {
                  if (
                    !(
                      "undefined" != typeof QuotaExceededError &&
                      p instanceof QuotaExceededError
                    )
                  )
                    throw p;
                }
              }
            if (o.length() < e)
              for (
                var f, h, d, _ = Math.floor(65536 * Math.random());
                o.length() < e;

              )
                for (
                  h = 16807 * (65535 & _),
                    h += (32767 & (f = 16807 * (_ >> 16))) << 16,
                    _ =
                      4294967295 &
                      (h = (2147483647 & (h += f >> 15)) + (h >> 31)),
                    l = 0;
                  l < 3;
                  ++l
                )
                  (d = _ >>> (l << 3)),
                    (d ^= Math.floor(256 * Math.random())),
                    o.putByte(255 & d);
            return o.getBytes(e);
          }
          return (
            (r.pools = o),
            (r.pool = 0),
            (r.generate = function (e, n) {
              if (!n) return r.generateSync(e);
              var s = r.plugin.cipher,
                o = r.plugin.increment,
                c = r.plugin.formatKey,
                u = r.plugin.formatSeed,
                p = a.util.createBuffer();
              (r.key = null),
                (function f(h) {
                  if (h) return n(h);
                  if (p.length() >= e) return n(null, p.getBytes(e));
                  if ((r.generated > 1048575 && (r.key = null), null === r.key))
                    return a.util.nextTick(function () {
                      !(function (e) {
                        if (r.pools[0].messageLength >= 32) return l(), e();
                        var n = (32 - r.pools[0].messageLength) << 5;
                        r.seedFile(n, function (n, a) {
                          if (n) return e(n);
                          r.collect(a), l(), e();
                        });
                      })(f);
                    });
                  var d = s(r.key, r.seed);
                  (r.generated += d.length),
                    p.putBytes(d),
                    (r.key = c(s(r.key, o(r.seed)))),
                    (r.seed = u(s(r.key, r.seed))),
                    a.util.setImmediate(f);
                })();
            }),
            (r.generateSync = function (e) {
              var n = r.plugin.cipher,
                s = r.plugin.increment,
                o = r.plugin.formatKey,
                c = r.plugin.formatSeed;
              r.key = null;
              for (var l = a.util.createBuffer(); l.length() < e; ) {
                r.generated > 1048575 && (r.key = null), null === r.key && u();
                var p = n(r.key, r.seed);
                (r.generated += p.length),
                  l.putBytes(p),
                  (r.key = o(n(r.key, s(r.seed)))),
                  (r.seed = c(n(r.key, r.seed)));
              }
              return l.getBytes(e);
            }),
            s
              ? ((r.seedFile = function (e, r) {
                  s.randomBytes(e, function (e, n) {
                    if (e) return r(e);
                    r(null, n.toString());
                  });
                }),
                (r.seedFileSync = function (e) {
                  return s.randomBytes(e).toString();
                }))
              : ((r.seedFile = function (e, r) {
                  try {
                    r(null, p(e));
                  } catch (n) {
                    r(n);
                  }
                }),
                (r.seedFileSync = p)),
            (r.collect = function (e) {
              for (var n = e.length, a = 0; a < n; ++a)
                r.pools[r.pool].update(e.substr(a, 1)),
                  (r.pool = 31 === r.pool ? 0 : r.pool + 1);
            }),
            (r.collectInt = function (e, n) {
              for (var a = "", s = 0; s < n; s += 8)
                a += String.fromCharCode((e >> s) & 255);
              r.collect(a);
            }),
            (r.registerWorker = function (e) {
              e === self
                ? (r.seedFile = function (e, r) {
                    self.addEventListener("message", function e(n) {
                      var a = n.data;
                      a.forge &&
                        a.forge.prng &&
                        (self.removeEventListener("message", e),
                        r(a.forge.prng.err, a.forge.prng.bytes));
                    }),
                      self.postMessage({ forge: { prng: { needed: e } } });
                  })
                : e.addEventListener("message", function (n) {
                    var a = n.data;
                    a.forge &&
                      a.forge.prng &&
                      r.seedFile(a.forge.prng.needed, function (r, n) {
                        e.postMessage({
                          forge: { prng: { err: r, bytes: n } },
                        });
                      });
                  });
            }),
            r
          );
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(1);
      var s = [
          217, 120, 249, 196, 25, 221, 181, 237, 40, 233, 253, 121, 74, 160,
          216, 157, 198, 126, 55, 131, 43, 118, 83, 142, 98, 76, 100, 136, 68,
          139, 251, 162, 23, 154, 89, 245, 135, 179, 79, 19, 97, 69, 109, 141,
          9, 129, 125, 50, 189, 143, 64, 235, 134, 183, 123, 11, 240, 149, 33,
          34, 92, 107, 78, 130, 84, 214, 101, 147, 206, 96, 178, 28, 115, 86,
          192, 20, 167, 140, 241, 220, 18, 117, 202, 31, 59, 190, 228, 209, 66,
          61, 212, 48, 163, 60, 182, 38, 111, 191, 14, 218, 70, 105, 7, 87, 39,
          242, 29, 155, 188, 148, 67, 3, 248, 17, 199, 246, 144, 239, 62, 231,
          6, 195, 213, 47, 200, 102, 30, 215, 8, 232, 234, 222, 128, 82, 238,
          247, 132, 170, 114, 172, 53, 77, 106, 42, 150, 26, 210, 113, 90, 21,
          73, 116, 75, 159, 208, 94, 4, 24, 164, 236, 194, 224, 65, 110, 15, 81,
          203, 204, 36, 145, 175, 80, 161, 244, 112, 57, 153, 124, 58, 133, 35,
          184, 180, 122, 252, 2, 54, 91, 37, 85, 151, 49, 45, 93, 250, 152, 227,
          138, 146, 174, 5, 223, 41, 16, 103, 108, 186, 201, 211, 0, 230, 207,
          225, 158, 168, 44, 99, 22, 1, 63, 88, 226, 137, 169, 13, 56, 52, 27,
          171, 51, 255, 176, 187, 72, 12, 95, 185, 177, 205, 46, 197, 243, 219,
          71, 229, 165, 156, 119, 10, 166, 32, 104, 254, 127, 193, 173,
        ],
        o = [1, 2, 3, 5];
      (e.exports = a.rc2 = a.rc2 || {}),
        (a.rc2.expandKey = function (e, r) {
          "string" == typeof e && (e = a.util.createBuffer(e)), (r = r || 128);
          var n,
            o = e,
            c = e.length(),
            u = r,
            l = Math.ceil(u / 8);
          for (n = c; n < 128; n++)
            o.putByte(s[(o.at(n - 1) + o.at(n - c)) & 255]);
          for (
            o.setAt(128 - l, s[o.at(128 - l) & (255 >> (7 & u))]), n = 127 - l;
            n >= 0;
            n--
          )
            o.setAt(n, s[o.at(n + 1) ^ o.at(n + l)]);
          return o;
        });
      var c = function (e, r, n) {
        var s,
          c,
          u,
          l,
          p = !1,
          f = null,
          h = null,
          d = null,
          _ = [];
        for (e = a.rc2.expandKey(e, r), u = 0; u < 64; u++)
          _.push(e.getInt16Le());
        n
          ? ((s = function (e) {
              for (u = 0; u < 4; u++) {
                var r, n;
                (e[u] +=
                  _[l] +
                  (e[(u + 3) % 4] & e[(u + 2) % 4]) +
                  (~e[(u + 3) % 4] & e[(u + 1) % 4])),
                  (e[u] =
                    (((r = e[u]) << (n = o[u])) & 65535) |
                    ((65535 & r) >> (16 - n))),
                  l++;
              }
            }),
            (c = function (e) {
              for (u = 0; u < 4; u++) e[u] += _[63 & e[(u + 3) % 4]];
            }))
          : ((s = function (e) {
              for (u = 3; u >= 0; u--) {
                var r, n;
                (e[u] =
                  ((65535 & (r = e[u])) >> (n = o[u])) |
                  ((r << (16 - n)) & 65535)),
                  (e[u] -=
                    _[l] +
                    (e[(u + 3) % 4] & e[(u + 2) % 4]) +
                    (~e[(u + 3) % 4] & e[(u + 1) % 4])),
                  l--;
              }
            }),
            (c = function (e) {
              for (u = 3; u >= 0; u--) e[u] -= _[63 & e[(u + 3) % 4]];
            }));
        var $ = function (e) {
            var r = [];
            for (u = 0; u < 4; u++) {
              var a = f.getInt16Le();
              null !== d && (n ? (a ^= d.getInt16Le()) : d.putInt16Le(a)),
                r.push(65535 & a);
            }
            l = n ? 0 : 63;
            for (var s = 0; s < e.length; s++)
              for (var o = 0; o < e[s][0]; o++) e[s][1](r);
            for (u = 0; u < 4; u++)
              null !== d && (n ? d.putInt16Le(r[u]) : (r[u] ^= d.getInt16Le())),
                h.putInt16Le(r[u]);
          },
          y = null;
        return (y = {
          start: function (e, r) {
            e && "string" == typeof e && (e = a.util.createBuffer(e)),
              (p = !1),
              (f = a.util.createBuffer()),
              (h = r || new a.util.createBuffer()),
              (d = e),
              (y.output = h);
          },
          update: function (e) {
            for (p || f.putBuffer(e); f.length() >= 8; )
              $([
                [5, s],
                [1, c],
                [6, s],
                [1, c],
                [5, s],
              ]);
          },
          finish: function (e) {
            var r = !0;
            if (n) {
              if (e) r = e(8, f, !n);
              else {
                var a = 8 === f.length() ? 8 : 8 - f.length();
                f.fillWithByte(a, a);
              }
            }
            if ((r && ((p = !0), y.update()), !n && (r = 0 === f.length()))) {
              if (e) r = e(8, h, !n);
              else {
                var s = h.length(),
                  o = h.at(s - 1);
                o > s ? (r = !1) : h.truncate(o);
              }
            }
            return r;
          },
        });
      };
      (a.rc2.startEncrypting = function (e, r, n) {
        var s = a.rc2.createEncryptionCipher(e, 128);
        return s.start(r, n), s;
      }),
        (a.rc2.createEncryptionCipher = function (e, r) {
          return c(e, r, !0);
        }),
        (a.rc2.startDecrypting = function (e, r, n) {
          var s = a.rc2.createDecryptionCipher(e, 128);
          return s.start(r, n), s;
        }),
        (a.rc2.createDecryptionCipher = function (e, r) {
          return c(e, r, !1);
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(1), n(2), n(9);
      var s = (e.exports = a.pkcs1 = a.pkcs1 || {});
      function o(e, r, n) {
        n || (n = a.md.sha1.create());
        for (var s = "", o = Math.ceil(r / n.digestLength), c = 0; c < o; ++c) {
          var u = String.fromCharCode(
            (c >> 24) & 255,
            (c >> 16) & 255,
            (c >> 8) & 255,
            255 & c
          );
          n.start(), n.update(e + u), (s += n.digest().getBytes());
        }
        return s.substring(0, r);
      }
      (s.encode_rsa_oaep = function (e, r, n) {
        "string" == typeof n
          ? ((s = n),
            (c = arguments[3] || void 0),
            (u = arguments[4] || void 0))
          : n &&
            ((s = n.label || void 0),
            (c = n.seed || void 0),
            (u = n.md || void 0),
            n.mgf1 && n.mgf1.md && (l = n.mgf1.md)),
          u ? u.start() : (u = a.md.sha1.create()),
          l || (l = u);
        var s,
          c,
          u,
          l,
          p,
          f = Math.ceil(e.n.bitLength() / 8),
          h = f - 2 * u.digestLength - 2;
        if (r.length > h)
          throw (
            (((p = Error(
              "RSAES-OAEP input message length is too long."
            )).length = r.length),
            (p.maxLength = h),
            p)
          );
        s || (s = ""), u.update(s, "raw");
        for (var d = u.digest(), _ = "", $ = h - r.length, y = 0; y < $; y++)
          _ += "\0";
        var g = d.getBytes() + _ + "\x01" + r;
        if (c) {
          if (c.length !== u.digestLength)
            throw (
              (((p = Error(
                "Invalid RSAES-OAEP seed. The seed length must match the digest length."
              )).seedLength = c.length),
              (p.digestLength = u.digestLength),
              p)
            );
        } else c = a.random.getBytes(u.digestLength);
        var v = o(c, f - u.digestLength - 1, l),
          m = a.util.xorBytes(g, v, g.length),
          C = o(m, u.digestLength, l);
        return "\0" + a.util.xorBytes(c, C, c.length) + m;
      }),
        (s.decode_rsa_oaep = function (e, r, n) {
          "string" == typeof n
            ? ((s = n), (c = arguments[3] || void 0))
            : n &&
              ((s = n.label || void 0),
              (c = n.md || void 0),
              n.mgf1 && n.mgf1.md && (u = n.mgf1.md));
          var s,
            c,
            u,
            l = Math.ceil(e.n.bitLength() / 8);
          if (r.length !== l)
            throw (
              (((m = Error(
                "RSAES-OAEP encoded message length is invalid."
              )).length = r.length),
              (m.expectedLength = l),
              m)
            );
          if (
            (void 0 === c ? (c = a.md.sha1.create()) : c.start(),
            u || (u = c),
            l < 2 * c.digestLength + 2)
          )
            throw Error("RSAES-OAEP key is too short for the hash function.");
          s || (s = ""), c.update(s, "raw");
          for (
            var p = c.digest().getBytes(),
              f = r.charAt(0),
              h = r.substring(1, c.digestLength + 1),
              d = r.substring(1 + c.digestLength),
              _ = o(d, c.digestLength, u),
              $ = a.util.xorBytes(h, _, h.length),
              y = o($, l - c.digestLength - 1, u),
              g = a.util.xorBytes(d, y, d.length),
              v = g.substring(0, c.digestLength),
              m = "\0" !== f,
              C = 0;
            C < c.digestLength;
            ++C
          )
            m |= p.charAt(C) !== v.charAt(C);
          for (
            var E = 1, S = c.digestLength, T = c.digestLength;
            T < g.length;
            T++
          ) {
            var B = g.charCodeAt(T),
              I = (1 & B) ^ 1;
            (m |= B & (E ? 65534 : 0)), (S += E &= I);
          }
          if (m || 1 !== g.charCodeAt(S))
            throw Error("Invalid RSAES-OAEP padding.");
          return g.substring(S + 1);
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(1),
        n(12),
        n(2),
        (function () {
          if (a.prime) e.exports = a.prime;
          else {
            var r = (e.exports = a.prime = a.prime || {}),
              n = a.jsbn.BigInteger,
              s = [6, 4, 2, 4, 2, 4, 6, 2],
              o = new n(null);
            o.fromInt(30);
            var c = function (e, r) {
              return e | r;
            };
            r.generateProbablePrime = function (e, r, s) {
              "function" == typeof r && ((s = r), (r = {}));
              var o,
                c,
                p,
                f,
                h = (r = r || {}).algorithm || "PRIMEINC";
              "string" == typeof h && (h = { name: h }),
                (h.options = h.options || {});
              var d = r.prng || a.random;
              if ("PRIMEINC" === h.name)
                return (
                  (o = e),
                  (c = {
                    nextBytes: function (e) {
                      for (
                        var r = d.getBytesSync(e.length), n = 0;
                        n < e.length;
                        ++n
                      )
                        e[n] = r.charCodeAt(n);
                    },
                  }),
                  (p = h.options),
                  (f = s),
                  "workers" in p
                    ? (function (e, r, s, o) {
                        if ("undefined" == typeof Worker) return u(e, r, s, o);
                        var c = l(e, r),
                          p = s.workers,
                          f = s.workLoad || 100,
                          h = (30 * f) / 8,
                          d = s.workerScript || "forge/prime.worker.js";
                        if (-1 === p)
                          return a.util.estimateCores(function (e, r) {
                            e && (r = 2), (p = r - 1), _();
                          });
                        function _() {
                          p = Math.max(1, p);
                          for (var a = [], s = 0; s < p; ++s)
                            a[s] = new Worker(d);
                          for (s = 0; s < p; ++s)
                            a[s].addEventListener("message", _);
                          var u = !1;
                          function _(s) {
                            if (!u) {
                              var p = s.data;
                              if (p.found) {
                                for (var d = 0; d < a.length; ++d)
                                  a[d].terminate();
                                return (u = !0), o(null, new n(p.prime, 16));
                              }
                              c.bitLength() > e && (c = l(e, r));
                              var _ = c.toString(16);
                              s.target.postMessage({ hex: _, workLoad: f }),
                                c.dAddOffset(h, 0);
                            }
                          }
                        }
                        _();
                      })(o, c, p, f)
                    : u(o, c, p, f)
                );
              throw Error("Invalid prime generation algorithm: " + h.name);
            };
          }
          function u(e, r, n, o) {
            var c,
              u = l(e, r),
              p =
                (c = u.bitLength()) <= 100
                  ? 27
                  : c <= 150
                  ? 18
                  : c <= 200
                  ? 15
                  : c <= 250
                  ? 12
                  : c <= 300
                  ? 9
                  : c <= 350
                  ? 8
                  : c <= 400
                  ? 7
                  : c <= 500
                  ? 6
                  : c <= 600
                  ? 5
                  : c <= 800
                  ? 4
                  : c <= 1250
                  ? 3
                  : 2;
            "millerRabinTests" in n && (p = n.millerRabinTests);
            var f = 10;
            "maxBlockTime" in n && (f = n.maxBlockTime),
              (function e(r, n, o, c, u, p, f) {
                var h = +new Date();
                do {
                  if (
                    (r.bitLength() > n && (r = l(n, o)), r.isProbablePrime(u))
                  )
                    return f(null, r);
                  r.dAddOffset(s[c++ % 8], 0);
                } while (p < 0 || +new Date() - h < p);
                a.util.setImmediate(function () {
                  e(r, n, o, c, u, p, f);
                });
              })(u, e, r, 0, p, f, o);
          }
          function l(e, r) {
            var a = new n(e, r),
              s = e - 1;
            return (
              a.testBit(s) || a.bitwiseTo(n.ONE.shiftLeft(s), c, a),
              a.dAddOffset(31 - a.mod(o).byteValue(), 0),
              a
            );
          }
        })();
    },
    function (e, r, n) {
      var a = n(0);
      n(3), n(8), n(6), n(29), n(22), n(2), n(11), n(9), n(1), n(17);
      var s = a.asn1,
        o = a.pki,
        c = (e.exports = a.pkcs12 = a.pkcs12 || {}),
        u = {
          name: "ContentInfo",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "ContentInfo.contentType",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.OID,
              constructed: !1,
              capture: "contentType",
            },
            {
              name: "ContentInfo.content",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              constructed: !0,
              captureAsn1: "content",
            },
          ],
        },
        l = {
          name: "PFX",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "PFX.version",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.INTEGER,
              constructed: !1,
              capture: "version",
            },
            u,
            {
              name: "PFX.macData",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              optional: !0,
              captureAsn1: "mac",
              value: [
                {
                  name: "PFX.macData.mac",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.SEQUENCE,
                  constructed: !0,
                  value: [
                    {
                      name: "PFX.macData.mac.digestAlgorithm",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.SEQUENCE,
                      constructed: !0,
                      value: [
                        {
                          name: "PFX.macData.mac.digestAlgorithm.algorithm",
                          tagClass: s.Class.UNIVERSAL,
                          type: s.Type.OID,
                          constructed: !1,
                          capture: "macAlgorithm",
                        },
                        {
                          name: "PFX.macData.mac.digestAlgorithm.parameters",
                          tagClass: s.Class.UNIVERSAL,
                          captureAsn1: "macAlgorithmParameters",
                        },
                      ],
                    },
                    {
                      name: "PFX.macData.mac.digest",
                      tagClass: s.Class.UNIVERSAL,
                      type: s.Type.OCTETSTRING,
                      constructed: !1,
                      capture: "macDigest",
                    },
                  ],
                },
                {
                  name: "PFX.macData.macSalt",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.OCTETSTRING,
                  constructed: !1,
                  capture: "macSalt",
                },
                {
                  name: "PFX.macData.iterations",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.INTEGER,
                  constructed: !1,
                  optional: !0,
                  capture: "macIterations",
                },
              ],
            },
          ],
        },
        p = {
          name: "SafeBag",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "SafeBag.bagId",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.OID,
              constructed: !1,
              capture: "bagId",
            },
            {
              name: "SafeBag.bagValue",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              constructed: !0,
              captureAsn1: "bagValue",
            },
            {
              name: "SafeBag.bagAttributes",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SET,
              constructed: !0,
              optional: !0,
              capture: "bagAttributes",
            },
          ],
        },
        f = {
          name: "Attribute",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "Attribute.attrId",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.OID,
              constructed: !1,
              capture: "oid",
            },
            {
              name: "Attribute.attrValues",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SET,
              constructed: !0,
              capture: "values",
            },
          ],
        },
        h = {
          name: "CertBag",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "CertBag.certId",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.OID,
              constructed: !1,
              capture: "certId",
            },
            {
              name: "CertBag.certValue",
              tagClass: s.Class.CONTEXT_SPECIFIC,
              constructed: !0,
              value: [
                {
                  name: "CertBag.certValue[0]",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Class.OCTETSTRING,
                  constructed: !1,
                  capture: "cert",
                },
              ],
            },
          ],
        };
      function d(e, r, n, a) {
        for (var s = [], o = 0; o < e.length; o++)
          for (var c = 0; c < e[o].safeBags.length; c++) {
            var u = e[o].safeBags[c];
            (void 0 !== a && u.type !== a) ||
              (null !== r
                ? void 0 !== u.attributes[r] &&
                  u.attributes[r].indexOf(n) >= 0 &&
                  s.push(u)
                : s.push(u));
          }
        return s;
      }
      function _(e) {
        if (e.composed || e.constructed) {
          for (var r = a.util.createBuffer(), n = 0; n < e.value.length; ++n)
            r.putBytes(e.value[n].value);
          (e.composed = e.constructed = !1), (e.value = r.getBytes());
        }
        return e;
      }
      function $(e, r) {
        var n = {},
          c = [];
        if (!s.validate(e, a.pkcs7.asn1.encryptedDataValidator, n, c))
          throw (
            (((u = Error("Cannot read EncryptedContentInfo.")).errors = c), u)
          );
        var u,
          l = s.derToOid(n.contentType);
        if (l !== o.oids.data)
          throw (
            (((u = Error(
              "PKCS#12 EncryptedContentInfo ContentType is not Data."
            )).oid = l),
            u)
          );
        l = s.derToOid(n.encAlgorithm);
        var p = o.pbe.getCipher(l, n.encParameter, r),
          f = _(n.encryptedContentAsn1),
          h = a.util.createBuffer(f.value);
        if ((p.update(h), !p.finish()))
          throw Error("Failed to decrypt PKCS#12 SafeContents.");
        return p.output.getBytes();
      }
      function y(e, r, n) {
        if (!r && 0 === e.length) return [];
        if (
          (e = s.fromDer(e, r)).tagClass !== s.Class.UNIVERSAL ||
          e.type !== s.Type.SEQUENCE ||
          !0 !== e.constructed
        )
          throw Error(
            "PKCS#12 SafeContents expected to be a SEQUENCE OF SafeBag."
          );
        for (var a = [], c = 0; c < e.value.length; c++) {
          var u,
            l = e.value[c],
            f = {},
            d = [];
          if (!s.validate(l, p, f, d))
            throw (((u = Error("Cannot read SafeBag.")).errors = d), u);
          var _,
            $,
            y = { type: s.derToOid(f.bagId), attributes: g(f.bagAttributes) };
          a.push(y);
          var v = f.bagValue.value[0];
          switch (y.type) {
            case o.oids.pkcs8ShroudedKeyBag:
              if (null === (v = o.decryptPrivateKeyInfo(v, n)))
                throw Error(
                  "Unable to decrypt PKCS#8 ShroudedKeyBag, wrong password?"
                );
            case o.oids.keyBag:
              try {
                y.key = o.privateKeyFromAsn1(v);
              } catch (m) {
                (y.key = null), (y.asn1 = v);
              }
              continue;
            case o.oids.certBag:
              (_ = h),
                ($ = function () {
                  if (s.derToOid(f.certId) !== o.oids.x509Certificate) {
                    var e = Error(
                      "Unsupported certificate type, only X.509 supported."
                    );
                    throw ((e.oid = s.derToOid(f.certId)), e);
                  }
                  var n = s.fromDer(f.cert, r);
                  try {
                    y.cert = o.certificateFromAsn1(n, !0);
                  } catch (a) {
                    (y.cert = null), (y.asn1 = n);
                  }
                });
              break;
            default:
              throw (
                (((u = Error("Unsupported PKCS#12 SafeBag type.")).oid =
                  y.type),
                u)
              );
          }
          if (void 0 !== _ && !s.validate(v, _, f, d))
            throw (
              (((u = Error("Cannot read PKCS#12 " + _.name)).errors = d), u)
            );
          $();
        }
        return a;
      }
      function g(e) {
        var r = {};
        if (void 0 !== e)
          for (var n = 0; n < e.length; ++n) {
            var a = {},
              c = [];
            if (!s.validate(e[n], f, a, c)) {
              var u = Error("Cannot read PKCS#12 BagAttribute.");
              throw ((u.errors = c), u);
            }
            var l = s.derToOid(a.oid);
            if (void 0 !== o.oids[l]) {
              r[o.oids[l]] = [];
              for (var p = 0; p < a.values.length; ++p)
                r[o.oids[l]].push(a.values[p].value);
            }
          }
        return r;
      }
      (c.pkcs12FromAsn1 = function (e, r, n) {
        "string" == typeof r ? ((n = r), (r = !0)) : void 0 === r && (r = !0);
        var p = {};
        if (!s.validate(e, l, p, []))
          throw (
            (((f = Error(
              "Cannot read PKCS#12 PFX. ASN.1 object is not an PKCS#12 PFX."
            )).errors = f),
            f)
          );
        var f,
          h = {
            version: p.version.charCodeAt(0),
            safeContents: [],
            getBags: function (e) {
              var r,
                n = {};
              return (
                "localKeyId" in e
                  ? (r = e.localKeyId)
                  : "localKeyIdHex" in e &&
                    (r = a.util.hexToBytes(e.localKeyIdHex)),
                void 0 === r &&
                  !("friendlyName" in e) &&
                  "bagType" in e &&
                  (n[e.bagType] = d(h.safeContents, null, null, e.bagType)),
                void 0 !== r &&
                  (n.localKeyId = d(
                    h.safeContents,
                    "localKeyId",
                    r,
                    e.bagType
                  )),
                "friendlyName" in e &&
                  (n.friendlyName = d(
                    h.safeContents,
                    "friendlyName",
                    e.friendlyName,
                    e.bagType
                  )),
                n
              );
            },
            getBagsByFriendlyName: function (e, r) {
              return d(h.safeContents, "friendlyName", e, r);
            },
            getBagsByLocalKeyId: function (e, r) {
              return d(h.safeContents, "localKeyId", e, r);
            },
          };
        if (3 !== p.version.charCodeAt(0))
          throw (
            (((f = Error(
              "PKCS#12 PFX of version other than 3 not supported."
            )).version = p.version.charCodeAt(0)),
            f)
          );
        if (s.derToOid(p.contentType) !== o.oids.data)
          throw (
            (((f = Error(
              "Only PKCS#12 PFX in password integrity mode supported."
            )).oid = s.derToOid(p.contentType)),
            f)
          );
        var g = p.content.value[0];
        if (g.tagClass !== s.Class.UNIVERSAL || g.type !== s.Type.OCTETSTRING)
          throw Error("PKCS#12 authSafe content data is not an OCTET STRING.");
        if (((g = _(g)), p.mac)) {
          var v = null,
            m = 0,
            C = s.derToOid(p.macAlgorithm);
          switch (C) {
            case o.oids.sha1:
              (v = a.md.sha1.create()), (m = 20);
              break;
            case o.oids.sha256:
              (v = a.md.sha256.create()), (m = 32);
              break;
            case o.oids.sha384:
              (v = a.md.sha384.create()), (m = 48);
              break;
            case o.oids.sha512:
              (v = a.md.sha512.create()), (m = 64);
              break;
            case o.oids.md5:
              (v = a.md.md5.create()), (m = 16);
          }
          if (null === v)
            throw Error("PKCS#12 uses unsupported MAC algorithm: " + C);
          var E = new a.util.ByteBuffer(p.macSalt),
            S =
              "macIterations" in p
                ? parseInt(a.util.bytesToHex(p.macIterations), 16)
                : 1,
            T = c.generateKey(n, E, 3, S, m, v),
            B = a.hmac.create();
          if (
            (B.start(v, T),
            B.update(g.value),
            B.getMac().getBytes() !== p.macDigest)
          )
            throw Error("PKCS#12 MAC could not be verified. Invalid password?");
        }
        return (
          (function (e, r, n, a) {
            if (
              (r = s.fromDer(r, n)).tagClass !== s.Class.UNIVERSAL ||
              r.type !== s.Type.SEQUENCE ||
              !0 !== r.constructed
            )
              throw Error(
                "PKCS#12 AuthenticatedSafe expected to be a SEQUENCE OF ContentInfo"
              );
            for (var c = 0; c < r.value.length; c++) {
              var l,
                p = r.value[c],
                f = {},
                h = [];
              if (!s.validate(p, u, f, h))
                throw (((l = Error("Cannot read ContentInfo.")).errors = h), l);
              var d = { encrypted: !1 },
                g = null,
                v = f.content.value[0];
              switch (s.derToOid(f.contentType)) {
                case o.oids.data:
                  if (
                    v.tagClass !== s.Class.UNIVERSAL ||
                    v.type !== s.Type.OCTETSTRING
                  )
                    throw Error(
                      "PKCS#12 SafeContents Data is not an OCTET STRING."
                    );
                  g = _(v).value;
                  break;
                case o.oids.encryptedData:
                  (g = $(v, a)), (d.encrypted = !0);
                  break;
                default:
                  throw (
                    (((l = Error(
                      "Unsupported PKCS#12 contentType."
                    )).contentType = s.derToOid(f.contentType)),
                    l)
                  );
              }
              (d.safeBags = y(g, n, a)), e.safeContents.push(d);
            }
          })(h, g.value, r, n),
          h
        );
      }),
        (c.toPkcs12Asn1 = function (e, r, n, u) {
          ((u = u || {}).saltSize = u.saltSize || 8),
            (u.count = u.count || 2048),
            (u.algorithm = u.algorithm || u.encAlgorithm || "aes128"),
            "useMac" in u || (u.useMac = !0),
            "localKeyId" in u || (u.localKeyId = null),
            "generateLocalKeyId" in u || (u.generateLocalKeyId = !0);
          var l,
            p = u.localKeyId;
          if (null !== p) p = a.util.hexToBytes(p);
          else if (u.generateLocalKeyId) {
            if (r) {
              var f = a.util.isArray(r) ? r[0] : r;
              "string" == typeof f && (f = o.certificateFromPem(f)),
                (N = a.md.sha1.create()).update(
                  s.toDer(o.certificateToAsn1(f)).getBytes()
                ),
                (p = N.digest().getBytes());
            } else p = a.random.getBytes(20);
          }
          var h = [];
          null !== p &&
            h.push(
              s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OID,
                  !1,
                  s.oidToDer(o.oids.localKeyId).getBytes()
                ),
                s.create(s.Class.UNIVERSAL, s.Type.SET, !0, [
                  s.create(s.Class.UNIVERSAL, s.Type.OCTETSTRING, !1, p),
                ]),
              ])
            ),
            "friendlyName" in u &&
              h.push(
                s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                  s.create(
                    s.Class.UNIVERSAL,
                    s.Type.OID,
                    !1,
                    s.oidToDer(o.oids.friendlyName).getBytes()
                  ),
                  s.create(s.Class.UNIVERSAL, s.Type.SET, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.BMPSTRING,
                      !1,
                      u.friendlyName
                    ),
                  ]),
                ])
              ),
            h.length > 0 &&
              (l = s.create(s.Class.UNIVERSAL, s.Type.SET, !0, h));
          var d = [],
            _ = [];
          null !== r && (_ = a.util.isArray(r) ? r : [r]);
          for (var $ = [], y = 0; y < _.length; ++y) {
            "string" == typeof (r = _[y]) && (r = o.certificateFromPem(r));
            var g = 0 === y ? l : void 0,
              v = o.certificateToAsn1(r),
              m = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OID,
                  !1,
                  s.oidToDer(o.oids.certBag).getBytes()
                ),
                s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                  s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.OID,
                      !1,
                      s.oidToDer(o.oids.x509Certificate).getBytes()
                    ),
                    s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                      s.create(
                        s.Class.UNIVERSAL,
                        s.Type.OCTETSTRING,
                        !1,
                        s.toDer(v).getBytes()
                      ),
                    ]),
                  ]),
                ]),
                g,
              ]);
            $.push(m);
          }
          if ($.length > 0) {
            var C = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, $),
              E = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OID,
                  !1,
                  s.oidToDer(o.oids.data).getBytes()
                ),
                s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                  s.create(
                    s.Class.UNIVERSAL,
                    s.Type.OCTETSTRING,
                    !1,
                    s.toDer(C).getBytes()
                  ),
                ]),
              ]);
            d.push(E);
          }
          var S = null;
          if (null !== e) {
            var T = o.wrapRsaPrivateKey(o.privateKeyToAsn1(e));
            S =
              null === n
                ? s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.OID,
                      !1,
                      s.oidToDer(o.oids.keyBag).getBytes()
                    ),
                    s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [T]),
                    l,
                  ])
                : s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.OID,
                      !1,
                      s.oidToDer(o.oids.pkcs8ShroudedKeyBag).getBytes()
                    ),
                    s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                      o.encryptPrivateKeyInfo(T, n, u),
                    ]),
                    l,
                  ]);
            var B = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [S]),
              I = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OID,
                  !1,
                  s.oidToDer(o.oids.data).getBytes()
                ),
                s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                  s.create(
                    s.Class.UNIVERSAL,
                    s.Type.OCTETSTRING,
                    !1,
                    s.toDer(B).getBytes()
                  ),
                ]),
              ]);
            d.push(I);
          }
          var A,
            b = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, d);
          if (u.useMac) {
            var N = a.md.sha1.create(),
              R = new a.util.ByteBuffer(a.random.getBytes(u.saltSize)),
              k = u.count,
              L = ((e = c.generateKey(n, R, 3, k, 20)), a.hmac.create());
            L.start(N, e), L.update(s.toDer(b).getBytes());
            var U = L.getMac();
            A = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
              s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                  s.create(
                    s.Class.UNIVERSAL,
                    s.Type.OID,
                    !1,
                    s.oidToDer(o.oids.sha1).getBytes()
                  ),
                  s.create(s.Class.UNIVERSAL, s.Type.NULL, !1, ""),
                ]),
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OCTETSTRING,
                  !1,
                  U.getBytes()
                ),
              ]),
              s.create(s.Class.UNIVERSAL, s.Type.OCTETSTRING, !1, R.getBytes()),
              s.create(
                s.Class.UNIVERSAL,
                s.Type.INTEGER,
                !1,
                s.integerToDer(k).getBytes()
              ),
            ]);
          }
          return s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
            s.create(
              s.Class.UNIVERSAL,
              s.Type.INTEGER,
              !1,
              s.integerToDer(3).getBytes()
            ),
            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
              s.create(
                s.Class.UNIVERSAL,
                s.Type.OID,
                !1,
                s.oidToDer(o.oids.data).getBytes()
              ),
              s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OCTETSTRING,
                  !1,
                  s.toDer(b).getBytes()
                ),
              ]),
            ]),
            A,
          ]);
        }),
        (c.generateKey = a.pbe.generatePkcs12Key);
    },
    function (e, r, n) {
      var a = n(0);
      n(3), n(1);
      var s = a.asn1,
        o = (e.exports = a.pkcs7asn1 = a.pkcs7asn1 || {});
      (a.pkcs7 = a.pkcs7 || {}), (a.pkcs7.asn1 = o);
      var c = {
        name: "ContentInfo",
        tagClass: s.Class.UNIVERSAL,
        type: s.Type.SEQUENCE,
        constructed: !0,
        value: [
          {
            name: "ContentInfo.ContentType",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.OID,
            constructed: !1,
            capture: "contentType",
          },
          {
            name: "ContentInfo.content",
            tagClass: s.Class.CONTEXT_SPECIFIC,
            type: 0,
            constructed: !0,
            optional: !0,
            captureAsn1: "content",
          },
        ],
      };
      o.contentInfoValidator = c;
      var u = {
        name: "EncryptedContentInfo",
        tagClass: s.Class.UNIVERSAL,
        type: s.Type.SEQUENCE,
        constructed: !0,
        value: [
          {
            name: "EncryptedContentInfo.contentType",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.OID,
            constructed: !1,
            capture: "contentType",
          },
          {
            name: "EncryptedContentInfo.contentEncryptionAlgorithm",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SEQUENCE,
            constructed: !0,
            value: [
              {
                name: "EncryptedContentInfo.contentEncryptionAlgorithm.algorithm",
                tagClass: s.Class.UNIVERSAL,
                type: s.Type.OID,
                constructed: !1,
                capture: "encAlgorithm",
              },
              {
                name: "EncryptedContentInfo.contentEncryptionAlgorithm.parameter",
                tagClass: s.Class.UNIVERSAL,
                captureAsn1: "encParameter",
              },
            ],
          },
          {
            name: "EncryptedContentInfo.encryptedContent",
            tagClass: s.Class.CONTEXT_SPECIFIC,
            type: 0,
            capture: "encryptedContent",
            captureAsn1: "encryptedContentAsn1",
          },
        ],
      };
      (o.envelopedDataValidator = {
        name: "EnvelopedData",
        tagClass: s.Class.UNIVERSAL,
        type: s.Type.SEQUENCE,
        constructed: !0,
        value: [
          {
            name: "EnvelopedData.Version",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.INTEGER,
            constructed: !1,
            capture: "version",
          },
          {
            name: "EnvelopedData.RecipientInfos",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SET,
            constructed: !0,
            captureAsn1: "recipientInfos",
          },
        ].concat(u),
      }),
        (o.encryptedDataValidator = {
          name: "EncryptedData",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "EncryptedData.Version",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.INTEGER,
              constructed: !1,
              capture: "version",
            },
          ].concat(u),
        });
      var l = {
        name: "SignerInfo",
        tagClass: s.Class.UNIVERSAL,
        type: s.Type.SEQUENCE,
        constructed: !0,
        value: [
          {
            name: "SignerInfo.version",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.INTEGER,
            constructed: !1,
          },
          {
            name: "SignerInfo.issuerAndSerialNumber",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SEQUENCE,
            constructed: !0,
            value: [
              {
                name: "SignerInfo.issuerAndSerialNumber.issuer",
                tagClass: s.Class.UNIVERSAL,
                type: s.Type.SEQUENCE,
                constructed: !0,
                captureAsn1: "issuer",
              },
              {
                name: "SignerInfo.issuerAndSerialNumber.serialNumber",
                tagClass: s.Class.UNIVERSAL,
                type: s.Type.INTEGER,
                constructed: !1,
                capture: "serial",
              },
            ],
          },
          {
            name: "SignerInfo.digestAlgorithm",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SEQUENCE,
            constructed: !0,
            value: [
              {
                name: "SignerInfo.digestAlgorithm.algorithm",
                tagClass: s.Class.UNIVERSAL,
                type: s.Type.OID,
                constructed: !1,
                capture: "digestAlgorithm",
              },
              {
                name: "SignerInfo.digestAlgorithm.parameter",
                tagClass: s.Class.UNIVERSAL,
                constructed: !1,
                captureAsn1: "digestParameter",
                optional: !0,
              },
            ],
          },
          {
            name: "SignerInfo.authenticatedAttributes",
            tagClass: s.Class.CONTEXT_SPECIFIC,
            type: 0,
            constructed: !0,
            optional: !0,
            capture: "authenticatedAttributes",
          },
          {
            name: "SignerInfo.digestEncryptionAlgorithm",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SEQUENCE,
            constructed: !0,
            capture: "signatureAlgorithm",
          },
          {
            name: "SignerInfo.encryptedDigest",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.OCTETSTRING,
            constructed: !1,
            capture: "signature",
          },
          {
            name: "SignerInfo.unauthenticatedAttributes",
            tagClass: s.Class.CONTEXT_SPECIFIC,
            type: 1,
            constructed: !0,
            optional: !0,
            capture: "unauthenticatedAttributes",
          },
        ],
      };
      (o.signedDataValidator = {
        name: "SignedData",
        tagClass: s.Class.UNIVERSAL,
        type: s.Type.SEQUENCE,
        constructed: !0,
        value: [
          {
            name: "SignedData.Version",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.INTEGER,
            constructed: !1,
            capture: "version",
          },
          {
            name: "SignedData.DigestAlgorithms",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SET,
            constructed: !0,
            captureAsn1: "digestAlgorithms",
          },
          c,
          {
            name: "SignedData.Certificates",
            tagClass: s.Class.CONTEXT_SPECIFIC,
            type: 0,
            optional: !0,
            captureAsn1: "certificates",
          },
          {
            name: "SignedData.CertificateRevocationLists",
            tagClass: s.Class.CONTEXT_SPECIFIC,
            type: 1,
            optional: !0,
            captureAsn1: "crls",
          },
          {
            name: "SignedData.SignerInfos",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SET,
            capture: "signerInfos",
            optional: !0,
            value: [l],
          },
        ],
      }),
        (o.recipientInfoValidator = {
          name: "RecipientInfo",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          value: [
            {
              name: "RecipientInfo.version",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.INTEGER,
              constructed: !1,
              capture: "version",
            },
            {
              name: "RecipientInfo.issuerAndSerial",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "RecipientInfo.issuerAndSerial.issuer",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.SEQUENCE,
                  constructed: !0,
                  captureAsn1: "issuer",
                },
                {
                  name: "RecipientInfo.issuerAndSerial.serialNumber",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.INTEGER,
                  constructed: !1,
                  capture: "serial",
                },
              ],
            },
            {
              name: "RecipientInfo.keyEncryptionAlgorithm",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "RecipientInfo.keyEncryptionAlgorithm.algorithm",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.OID,
                  constructed: !1,
                  capture: "encAlgorithm",
                },
                {
                  name: "RecipientInfo.keyEncryptionAlgorithm.parameter",
                  tagClass: s.Class.UNIVERSAL,
                  constructed: !1,
                  captureAsn1: "encParameter",
                  optional: !0,
                },
              ],
            },
            {
              name: "RecipientInfo.encryptedKey",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.OCTETSTRING,
              constructed: !1,
              capture: "encKey",
            },
          ],
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(1),
        (a.mgf = a.mgf || {}),
        ((e.exports = a.mgf.mgf1 = a.mgf1 = a.mgf1 || {}).create = function (
          e
        ) {
          return {
            generate: function (r, n) {
              for (
                var s = new a.util.ByteBuffer(),
                  o = Math.ceil(n / e.digestLength),
                  c = 0;
                c < o;
                c++
              ) {
                var u = new a.util.ByteBuffer();
                u.putInt32(c),
                  e.start(),
                  e.update(r + u.getBytes()),
                  s.putBuffer(e.digest());
              }
              return s.truncate(s.length() - n), s.getBytes();
            },
          };
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(4), n(1);
      var s = (e.exports = a.sha512 = a.sha512 || {});
      a.md.sha512 = a.md.algorithms.sha512 = s;
      var o = (a.sha384 = a.sha512.sha384 = a.sha512.sha384 || {});
      (o.create = function () {
        return s.create("SHA-384");
      }),
        (a.md.sha384 = a.md.algorithms.sha384 = o),
        (a.sha512.sha256 = a.sha512.sha256 || {
          create: function () {
            return s.create("SHA-512/256");
          },
        }),
        (a.md["sha512/256"] = a.md.algorithms["sha512/256"] = a.sha512.sha256),
        (a.sha512.sha224 = a.sha512.sha224 || {
          create: function () {
            return s.create("SHA-512/224");
          },
        }),
        (a.md["sha512/224"] = a.md.algorithms["sha512/224"] = a.sha512.sha224),
        (s.create = function (e) {
          if (
            (u ||
              ((c = "\x80"),
              (c += a.util.fillString("\0", 128)),
              (l = [
                [1116352408, 3609767458],
                [1899447441, 602891725],
                [3049323471, 3964484399],
                [3921009573, 2173295548],
                [961987163, 4081628472],
                [1508970993, 3053834265],
                [2453635748, 2937671579],
                [2870763221, 3664609560],
                [3624381080, 2734883394],
                [310598401, 1164996542],
                [607225278, 1323610764],
                [1426881987, 3590304994],
                [1925078388, 4068182383],
                [2162078206, 991336113],
                [2614888103, 633803317],
                [3248222580, 3479774868],
                [3835390401, 2666613458],
                [4022224774, 944711139],
                [264347078, 2341262773],
                [604807628, 2007800933],
                [770255983, 1495990901],
                [1249150122, 1856431235],
                [1555081692, 3175218132],
                [1996064986, 2198950837],
                [2554220882, 3999719339],
                [2821834349, 766784016],
                [2952996808, 2566594879],
                [3210313671, 3203337956],
                [3336571891, 1034457026],
                [3584528711, 2466948901],
                [113926993, 3758326383],
                [338241895, 168717936],
                [666307205, 1188179964],
                [773529912, 1546045734],
                [1294757372, 1522805485],
                [1396182291, 2643833823],
                [1695183700, 2343527390],
                [1986661051, 1014477480],
                [2177026350, 1206759142],
                [2456956037, 344077627],
                [2730485921, 1290863460],
                [2820302411, 3158454273],
                [3259730800, 3505952657],
                [3345764771, 106217008],
                [3516065817, 3606008344],
                [3600352804, 1432725776],
                [4094571909, 1467031594],
                [275423344, 851169720],
                [430227734, 3100823752],
                [506948616, 1363258195],
                [659060556, 3750685593],
                [883997877, 3785050280],
                [958139571, 3318307427],
                [1322822218, 3812723403],
                [1537002063, 2003034995],
                [1747873779, 3602036899],
                [1955562222, 1575990012],
                [2024104815, 1125592928],
                [2227730452, 2716904306],
                [2361852424, 442776044],
                [2428436474, 593698344],
                [2756734187, 3733110249],
                [3204031479, 2999351573],
                [3329325298, 3815920427],
                [3391569614, 3928383900],
                [3515267271, 566280711],
                [3940187606, 3454069534],
                [4118630271, 4000239992],
                [116418474, 1914138554],
                [174292421, 2731055270],
                [289380356, 3203993006],
                [460393269, 320620315],
                [685471733, 587496836],
                [852142971, 1086792851],
                [1017036298, 365543100],
                [1126000580, 2618297676],
                [1288033470, 3409855158],
                [1501505948, 4234509866],
                [1607167915, 987167468],
                [1816402316, 1246189591],
              ]),
              ((p = {})["SHA-512"] = [
                [1779033703, 4089235720],
                [3144134277, 2227873595],
                [1013904242, 4271175723],
                [2773480762, 1595750129],
                [1359893119, 2917565137],
                [2600822924, 725511199],
                [528734635, 4215389547],
                [1541459225, 327033209],
              ]),
              (p["SHA-384"] = [
                [3418070365, 3238371032],
                [1654270250, 914150663],
                [2438529370, 812702999],
                [355462360, 4144912697],
                [1731405415, 4290775857],
                [2394180231, 1750603025],
                [3675008525, 1694076839],
                [1203062813, 3204075428],
              ]),
              (p["SHA-512/256"] = [
                [573645204, 4230739756],
                [2673172387, 3360449730],
                [596883563, 1867755857],
                [2520282905, 1497426621],
                [2519219938, 2827943907],
                [3193839141, 1401305490],
                [721525244, 746961066],
                [246885852, 2177182882],
              ]),
              (p["SHA-512/224"] = [
                [2352822216, 424955298],
                [1944164710, 2312950998],
                [502970286, 855612546],
                [1738396948, 1479516111],
                [258812777, 2077511080],
                [2011393907, 79989058],
                [1067287976, 1780299464],
                [286451373, 2446758561],
              ]),
              (u = !0)),
            void 0 === e && (e = "SHA-512"),
            !(e in p))
          )
            throw Error("Invalid SHA-512 algorithm: " + e);
          for (
            var r = p[e],
              n = null,
              s = a.util.createBuffer(),
              o = Array(80),
              h = 0;
            h < 80;
            ++h
          )
            o[h] = [, ,];
          var d = 64;
          switch (e) {
            case "SHA-384":
              d = 48;
              break;
            case "SHA-512/256":
              d = 32;
              break;
            case "SHA-512/224":
              d = 28;
          }
          var _ = {
            algorithm: e.replace("-", "").toLowerCase(),
            blockLength: 128,
            digestLength: d,
            messageLength: 0,
            fullMessageLength: null,
            messageLengthSize: 16,
            start: function () {
              (_.messageLength = 0),
                (_.fullMessageLength = _.messageLength128 = []);
              for (var e = _.messageLengthSize / 4, o = 0; o < e; ++o)
                _.fullMessageLength.push(0);
              for (
                s = a.util.createBuffer(), n = Array(r.length), o = 0;
                o < r.length;
                ++o
              )
                n[o] = r[o].slice(0);
              return _;
            },
          };
          return (
            _.start(),
            (_.update = function (e, r) {
              "utf8" === r && (e = a.util.encodeUtf8(e));
              var c = e.length;
              (_.messageLength += c), (c = [(c / 4294967296) >>> 0, c >>> 0]);
              for (var u = _.fullMessageLength.length - 1; u >= 0; --u)
                (_.fullMessageLength[u] += c[1]),
                  (c[1] = c[0] + ((_.fullMessageLength[u] / 4294967296) >>> 0)),
                  (_.fullMessageLength[u] = _.fullMessageLength[u] >>> 0),
                  (c[0] = (c[1] / 4294967296) >>> 0);
              return (
                s.putBytes(e),
                f(n, o, s),
                (s.read > 2048 || 0 === s.length()) && s.compact(),
                _
              );
            }),
            (_.digest = function () {
              var r = a.util.createBuffer();
              r.putBytes(s.bytes());
              var u,
                l =
                  (_.fullMessageLength[_.fullMessageLength.length - 1] +
                    _.messageLengthSize) &
                  (_.blockLength - 1);
              r.putBytes(c.substr(0, _.blockLength - l));
              for (
                var p = 8 * _.fullMessageLength[0], h = 0;
                h < _.fullMessageLength.length - 1;
                ++h
              )
                (p +=
                  ((u = 8 * _.fullMessageLength[h + 1]) / 4294967296) >>> 0),
                  r.putInt32(p >>> 0),
                  (p = u >>> 0);
              r.putInt32(p);
              var d = Array(n.length);
              for (h = 0; h < n.length; ++h) d[h] = n[h].slice(0);
              f(d, o, r);
              var $,
                y = a.util.createBuffer();
              for (
                h = 0,
                  $ =
                    "SHA-512" === e
                      ? d.length
                      : "SHA-384" === e
                      ? d.length - 2
                      : d.length - 4;
                h < $;
                ++h
              )
                y.putInt32(d[h][0]),
                  (h === $ - 1 && "SHA-512/224" === e) || y.putInt32(d[h][1]);
              return y;
            }),
            _
          );
        });
      var c = null,
        u = !1,
        l = null,
        p = null;
      function f(e, r, n) {
        for (
          var a,
            s,
            o,
            c,
            u,
            p,
            f,
            h,
            d,
            _,
            $,
            y,
            g,
            v,
            m,
            C,
            E,
            S,
            T,
            B,
            I,
            A,
            b,
            N,
            R,
            k,
            L,
            U,
            D,
            w,
            P,
            x,
            V,
            O = n.length();
          O >= 128;

        ) {
          for (L = 0; L < 16; ++L)
            (r[L][0] = n.getInt32() >>> 0), (r[L][1] = n.getInt32() >>> 0);
          for (; L < 80; ++L)
            (a =
              ((((U = (w = r[L - 2])[0]) >>> 19) | ((D = w[1]) << 13)) ^
                ((D >>> 29) | (U << 3)) ^
                (U >>> 6)) >>>
              0),
              (s =
                (((U << 13) | (D >>> 19)) ^
                  ((D << 3) | (U >>> 29)) ^
                  ((U << 26) | (D >>> 6))) >>>
                0),
              (o =
                ((((U = (x = r[L - 15])[0]) >>> 1) | ((D = x[1]) << 31)) ^
                  ((U >>> 8) | (D << 24)) ^
                  (U >>> 7)) >>>
                0),
              (c =
                (((U << 31) | (D >>> 1)) ^
                  ((U << 24) | (D >>> 8)) ^
                  ((U << 25) | (D >>> 7))) >>>
                0),
              (P = r[L - 7]),
              (V = r[L - 16]),
              (D = s + P[1] + c + V[1]),
              (r[L][0] =
                (a + P[0] + o + V[0] + ((D / 4294967296) >>> 0)) >>> 0),
              (r[L][1] = D >>> 0);
          for (
            $ = e[0][0],
              y = e[0][1],
              g = e[1][0],
              v = e[1][1],
              m = e[2][0],
              C = e[2][1],
              E = e[3][0],
              S = e[3][1],
              T = e[4][0],
              B = e[4][1],
              I = e[5][0],
              A = e[5][1],
              b = e[6][0],
              N = e[6][1],
              R = e[7][0],
              k = e[7][1],
              L = 0;
            L < 80;
            ++L
          )
            (f =
              (((T >>> 14) | (B << 18)) ^
                ((T >>> 18) | (B << 14)) ^
                ((B >>> 9) | (T << 23))) >>>
              0),
              (h = (b ^ (T & (I ^ b))) >>> 0),
              (u =
                ((($ >>> 28) | (y << 4)) ^
                  ((y >>> 2) | ($ << 30)) ^
                  ((y >>> 7) | ($ << 25))) >>>
                0),
              (p =
                ((($ << 4) | (y >>> 28)) ^
                  ((y << 30) | ($ >>> 2)) ^
                  ((y << 25) | ($ >>> 7))) >>>
                0),
              (d = (($ & g) | (m & ($ ^ g))) >>> 0),
              (_ = ((y & v) | (C & (y ^ v))) >>> 0),
              (D =
                k +
                ((((T << 18) | (B >>> 14)) ^
                  ((T << 14) | (B >>> 18)) ^
                  ((B << 23) | (T >>> 9))) >>>
                  0) +
                ((N ^ (B & (A ^ N))) >>> 0) +
                l[L][1] +
                r[L][1]),
              (a =
                (R + f + h + l[L][0] + r[L][0] + ((D / 4294967296) >>> 0)) >>>
                0),
              (s = D >>> 0),
              (o = (u + d + (((D = p + _) / 4294967296) >>> 0)) >>> 0),
              (c = D >>> 0),
              (R = b),
              (k = N),
              (b = I),
              (N = A),
              (I = T),
              (A = B),
              (T = (E + a + (((D = S + s) / 4294967296) >>> 0)) >>> 0),
              (B = D >>> 0),
              (E = m),
              (S = C),
              (m = g),
              (C = v),
              (g = $),
              (v = y),
              ($ = (a + o + (((D = s + c) / 4294967296) >>> 0)) >>> 0),
              (y = D >>> 0);
          (D = e[0][1] + y),
            (e[0][0] = (e[0][0] + $ + ((D / 4294967296) >>> 0)) >>> 0),
            (e[0][1] = D >>> 0),
            (D = e[1][1] + v),
            (e[1][0] = (e[1][0] + g + ((D / 4294967296) >>> 0)) >>> 0),
            (e[1][1] = D >>> 0),
            (D = e[2][1] + C),
            (e[2][0] = (e[2][0] + m + ((D / 4294967296) >>> 0)) >>> 0),
            (e[2][1] = D >>> 0),
            (D = e[3][1] + S),
            (e[3][0] = (e[3][0] + E + ((D / 4294967296) >>> 0)) >>> 0),
            (e[3][1] = D >>> 0),
            (D = e[4][1] + B),
            (e[4][0] = (e[4][0] + T + ((D / 4294967296) >>> 0)) >>> 0),
            (e[4][1] = D >>> 0),
            (D = e[5][1] + A),
            (e[5][0] = (e[5][0] + I + ((D / 4294967296) >>> 0)) >>> 0),
            (e[5][1] = D >>> 0),
            (D = e[6][1] + N),
            (e[6][0] = (e[6][0] + b + ((D / 4294967296) >>> 0)) >>> 0),
            (e[6][1] = D >>> 0),
            (D = e[7][1] + k),
            (e[7][0] = (e[7][0] + R + ((D / 4294967296) >>> 0)) >>> 0),
            (e[7][1] = D >>> 0),
            (O -= 128);
        }
      }
    },
    function (e, r, n) {
      e.exports = n(33);
    },
    function (e, r, n) {
      (e.exports = n(0)),
        n(5),
        n(36),
        n(3),
        n(13),
        n(10),
        n(38),
        n(8),
        n(40),
        n(41),
        n(42),
        n(30),
        n(15),
        n(7),
        n(26),
        n(28),
        n(43),
        n(21),
        n(27),
        n(24),
        n(18),
        n(2),
        n(25),
        n(44),
        n(20),
        n(1);
    },
    function (e, r) {
      var n;
      n = (function () {
        return this;
      })();
      try {
        n = n || Function("return this")();
      } catch (a) {}
      e.exports = n;
    },
    function (e, r) {
      var n = {};
      e.exports = n;
      var a = {};
      (n.encode = function (e, r, n) {
        if ("string" != typeof r)
          throw TypeError('"alphabet" must be a string.');
        if (void 0 !== n && "number" != typeof n)
          throw TypeError('"maxline" must be a number.');
        var a = "";
        if (e instanceof Uint8Array) {
          var s = 0,
            o = r.length,
            c = r.charAt(0),
            u = [0];
          for (s = 0; s < e.length; ++s) {
            for (var l = 0, p = e[s]; l < u.length; ++l)
              (p += u[l] << 8), (u[l] = p % o), (p = (p / o) | 0);
            for (; p > 0; ) u.push(p % o), (p = (p / o) | 0);
          }
          for (s = 0; 0 === e[s] && s < e.length - 1; ++s) a += c;
          for (s = u.length - 1; s >= 0; --s) a += r[u[s]];
        } else
          a = (function (e, r) {
            var n = 0,
              a = r.length,
              s = r.charAt(0),
              o = [0];
            for (n = 0; n < e.length(); ++n) {
              for (var c = 0, u = e.at(n); c < o.length; ++c)
                (u += o[c] << 8), (o[c] = u % a), (u = (u / a) | 0);
              for (; u > 0; ) o.push(u % a), (u = (u / a) | 0);
            }
            var l = "";
            for (n = 0; 0 === e.at(n) && n < e.length() - 1; ++n) l += s;
            for (n = o.length - 1; n >= 0; --n) l += r[o[n]];
            return l;
          })(e, r);
        if (n) {
          var f = RegExp(".{1," + n + "}", "g");
          a = a.match(f).join("\r\n");
        }
        return a;
      }),
        (n.decode = function (e, r) {
          if ("string" != typeof e)
            throw TypeError('"input" must be a string.');
          if ("string" != typeof r)
            throw TypeError('"alphabet" must be a string.');
          var n = a[r];
          if (!n) {
            n = a[r] = [];
            for (var s = 0; s < r.length; ++s) n[r.charCodeAt(s)] = s;
          }
          e = e.replace(/\s/g, "");
          var o = r.length,
            c = r.charAt(0),
            u = [0];
          for (s = 0; s < e.length; s++) {
            var l = n[e.charCodeAt(s)];
            if (void 0 === l) return;
            for (var p = 0, f = l; p < u.length; ++p)
              (f += u[p] * o), (u[p] = 255 & f), (f >>= 8);
            for (; f > 0; ) u.push(255 & f), (f >>= 8);
          }
          for (var h = 0; e[h] === c && h < e.length - 1; ++h) u.push(0);
          return "undefined" != typeof Buffer
            ? Buffer.from(u.reverse())
            : new Uint8Array(u.reverse());
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(5), n(20);
      var s = (e.exports = a.tls);
      function o(e, r, n) {
        var o = r.entity === a.tls.ConnectionEnd.client;
        (e.read.cipherState = {
          init: !1,
          cipher: a.cipher.createDecipher(
            "AES-CBC",
            o ? n.keys.server_write_key : n.keys.client_write_key
          ),
          iv: o ? n.keys.server_write_IV : n.keys.client_write_IV,
        }),
          (e.write.cipherState = {
            init: !1,
            cipher: a.cipher.createCipher(
              "AES-CBC",
              o ? n.keys.client_write_key : n.keys.server_write_key
            ),
            iv: o ? n.keys.client_write_IV : n.keys.server_write_IV,
          }),
          (e.read.cipherFunction = p),
          (e.write.cipherFunction = c),
          (e.read.macLength = e.write.macLength = n.mac_length),
          (e.read.macFunction = e.write.macFunction = s.hmac_sha1);
      }
      function c(e, r) {
        var n,
          o = !1,
          c = r.macFunction(r.macKey, r.sequenceNumber, e);
        e.fragment.putBytes(c),
          r.updateSequenceNumber(),
          (n =
            e.version.minor === s.Versions.TLS_1_0.minor
              ? r.cipherState.init
                ? null
                : r.cipherState.iv
              : a.random.getBytesSync(16)),
          (r.cipherState.init = !0);
        var l = r.cipherState.cipher;
        return (
          l.start({ iv: n }),
          e.version.minor >= s.Versions.TLS_1_1.minor && l.output.putBytes(n),
          l.update(e.fragment),
          l.finish(u) &&
            ((e.fragment = l.output),
            (e.length = e.fragment.length()),
            (o = !0)),
          o
        );
      }
      function u(e, r, n) {
        if (!n) {
          var a = e - (r.length() % e);
          r.fillWithByte(a - 1, a);
        }
        return !0;
      }
      function l(e, r, n) {
        var a = !0;
        if (n) {
          for (var s = r.length(), o = r.last(), c = s - 1 - o; c < s - 1; ++c)
            a = a && r.at(c) == o;
          a && r.truncate(o + 1);
        }
        return a;
      }
      function p(e, r) {
        var n,
          o = !1;
        (n =
          e.version.minor === s.Versions.TLS_1_0.minor
            ? r.cipherState.init
              ? null
              : r.cipherState.iv
            : e.fragment.getBytes(16)),
          (r.cipherState.init = !0);
        var c = r.cipherState.cipher;
        c.start({ iv: n }), c.update(e.fragment), (o = c.finish(l));
        var u = r.macLength,
          p = a.random.getBytesSync(u),
          f = c.output.length();
        f >= u
          ? ((e.fragment = c.output.getBytes(f - u)),
            (p = c.output.getBytes(u)))
          : (e.fragment = c.output.getBytes()),
          (e.fragment = a.util.createBuffer(e.fragment)),
          (e.length = e.fragment.length());
        var h,
          d,
          _,
          $,
          y = r.macFunction(r.macKey, r.sequenceNumber, e);
        return (
          r.updateSequenceNumber(),
          (o =
            ((h = r.macKey),
            (d = p),
            (_ = y),
            ($ = a.hmac.create()).start("SHA1", h),
            $.update(d),
            (d = $.digest().getBytes()),
            $.start(null, null),
            $.update(_),
            d === (_ = $.digest().getBytes()) && o))
        );
      }
      (s.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA = {
        id: [0, 47],
        name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        initSecurityParameters: function (e) {
          (e.bulk_cipher_algorithm = s.BulkCipherAlgorithm.aes),
            (e.cipher_type = s.CipherType.block),
            (e.enc_key_length = 16),
            (e.block_length = 16),
            (e.fixed_iv_length = 16),
            (e.record_iv_length = 16),
            (e.mac_algorithm = s.MACAlgorithm.hmac_sha1),
            (e.mac_length = 20),
            (e.mac_key_length = 20);
        },
        initConnectionState: o,
      }),
        (s.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA = {
          id: [0, 53],
          name: "TLS_RSA_WITH_AES_256_CBC_SHA",
          initSecurityParameters: function (e) {
            (e.bulk_cipher_algorithm = s.BulkCipherAlgorithm.aes),
              (e.cipher_type = s.CipherType.block),
              (e.enc_key_length = 32),
              (e.block_length = 16),
              (e.fixed_iv_length = 16),
              (e.record_iv_length = 16),
              (e.mac_algorithm = s.MACAlgorithm.hmac_sha1),
              (e.mac_length = 20),
              (e.mac_key_length = 20);
          },
          initConnectionState: o,
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(30), (e.exports = a.mgf = a.mgf || {}), (a.mgf.mgf1 = a.mgf1);
    },
    function (e, r, n) {
      var a = n(0);
      n(12), n(2), n(31), n(1);
      var s = n(39),
        o = s.publicKeyValidator,
        c = s.privateKeyValidator;
      if (void 0 === u) var u = a.jsbn.BigInteger;
      var l = a.util.ByteBuffer,
        p = "undefined" == typeof Buffer ? Uint8Array : Buffer;
      (a.pki = a.pki || {}),
        (e.exports = a.pki.ed25519 = a.ed25519 = a.ed25519 || {});
      var f = a.ed25519;
      function h(e) {
        var r = e.message;
        if (r instanceof Uint8Array || r instanceof p) return r;
        var n = e.encoding;
        if (void 0 === r) {
          if (!e.md)
            throw TypeError('"options.message" or "options.md" not specified.');
          (r = e.md.digest().getBytes()), (n = "binary");
        }
        if ("string" == typeof r && !n)
          throw TypeError('"options.encoding" must be "binary" or "utf8".');
        if ("string" == typeof r) {
          if ("undefined" != typeof Buffer) return Buffer.from(r, n);
          r = new l(r, n);
        } else if (!(r instanceof l))
          throw TypeError(
            '"options.message" must be a node.js Buffer, a Uint8Array, a forge ByteBuffer, or a string with "options.encoding" specifying its encoding.'
          );
        for (var a = new p(r.length()), s = 0; s < a.length; ++s)
          a[s] = r.at(s);
        return a;
      }
      (f.constants = {}),
        (f.constants.PUBLIC_KEY_BYTE_LENGTH = 32),
        (f.constants.PRIVATE_KEY_BYTE_LENGTH = 64),
        (f.constants.SEED_BYTE_LENGTH = 32),
        (f.constants.SIGN_BYTE_LENGTH = 64),
        (f.constants.HASH_BYTE_LENGTH = 64),
        (f.generateKeyPair = function (e) {
          var r = (e = e || {}).seed;
          if (void 0 === r)
            r = a.random.getBytesSync(f.constants.SEED_BYTE_LENGTH);
          else if ("string" == typeof r) {
            if (r.length !== f.constants.SEED_BYTE_LENGTH)
              throw TypeError(
                '"seed" must be ' +
                  f.constants.SEED_BYTE_LENGTH +
                  " bytes in length."
              );
          } else if (!(r instanceof Uint8Array))
            throw TypeError(
              '"seed" must be a node.js Buffer, Uint8Array, or a binary string.'
            );
          r = h({ message: r, encoding: "binary" });
          for (
            var n = new p(f.constants.PUBLIC_KEY_BYTE_LENGTH),
              s = new p(f.constants.PRIVATE_KEY_BYTE_LENGTH),
              o = 0;
            o < 32;
            ++o
          )
            s[o] = r[o];
          return (
            (function (e, r) {
              var n,
                a = [x(), x(), x(), x()],
                s = E(r, 32);
              for (
                s[0] &= 248, s[31] &= 127, s[31] |= 64, U(a, s), A(e, a), n = 0;
                n < 32;
                ++n
              )
                r[n + 32] = e[n];
            })(n, s),
            { publicKey: n, privateKey: s }
          );
        }),
        (f.privateKeyFromAsn1 = function (e) {
          var r = {},
            n = [];
          if (!a.asn1.validate(e, c, r, n)) {
            var s = Error("Invalid Key.");
            throw ((s.errors = n), s);
          }
          var o = a.asn1.derToOid(r.privateKeyOid),
            u = a.oids.EdDSA25519;
          if (o !== u)
            throw Error('Invalid OID "' + o + '"; OID must be "' + u + '".');
          var l = r.privateKey;
          return {
            privateKeyBytes: h({
              message: a.asn1.fromDer(l).value,
              encoding: "binary",
            }),
          };
        }),
        (f.publicKeyFromAsn1 = function (e) {
          var r = {},
            n = [];
          if (!a.asn1.validate(e, o, r, n)) {
            var s = Error("Invalid Key.");
            throw ((s.errors = n), s);
          }
          var c = a.asn1.derToOid(r.publicKeyOid),
            u = a.oids.EdDSA25519;
          if (c !== u)
            throw Error('Invalid OID "' + c + '"; OID must be "' + u + '".');
          var l = r.ed25519PublicKey;
          if (l.length !== f.constants.PUBLIC_KEY_BYTE_LENGTH)
            throw Error("Key length is invalid.");
          return h({ message: l, encoding: "binary" });
        }),
        (f.publicKeyFromPrivateKey = function (e) {
          var r = h({ message: (e = e || {}).privateKey, encoding: "binary" });
          if (r.length !== f.constants.PRIVATE_KEY_BYTE_LENGTH)
            throw TypeError(
              '"options.privateKey" must have a byte length of ' +
                f.constants.PRIVATE_KEY_BYTE_LENGTH
            );
          for (
            var n = new p(f.constants.PUBLIC_KEY_BYTE_LENGTH), a = 0;
            a < n.length;
            ++a
          )
            n[a] = r[32 + a];
          return n;
        }),
        (f.sign = function (e) {
          var r = h((e = e || {})),
            n = h({ message: e.privateKey, encoding: "binary" });
          if (n.length === f.constants.SEED_BYTE_LENGTH)
            n = f.generateKeyPair({ seed: n }).privateKey;
          else if (n.length !== f.constants.PRIVATE_KEY_BYTE_LENGTH)
            throw TypeError(
              '"options.privateKey" must have a byte length of ' +
                f.constants.SEED_BYTE_LENGTH +
                " or " +
                f.constants.PRIVATE_KEY_BYTE_LENGTH
            );
          var a = new p(f.constants.SIGN_BYTE_LENGTH + r.length);
          !(function (e, r, n, a) {
            var s,
              o,
              c = new Float64Array(64),
              u = [x(), x(), x(), x()],
              l = E(a, 32);
            for (l[0] &= 248, l[31] &= 127, l[31] |= 64, s = 0; s < n; ++s)
              e[64 + s] = r[s];
            for (s = 0; s < 32; ++s) e[32 + s] = l[32 + s];
            var p = E(e.subarray(32), n + 32);
            for (T(p), U(u, p), A(e, u), s = 32; s < 64; ++s) e[s] = a[s];
            var f = E(e, n + 64);
            for (T(f), s = 32; s < 64; ++s) c[s] = 0;
            for (s = 0; s < 32; ++s) c[s] = p[s];
            for (s = 0; s < 32; ++s)
              for (o = 0; o < 32; o++) c[s + o] += f[s] * l[o];
            S(e.subarray(32), c);
          })(a, r, r.length, n);
          for (
            var s = new p(f.constants.SIGN_BYTE_LENGTH), o = 0;
            o < s.length;
            ++o
          )
            s[o] = a[o];
          return s;
        }),
        (f.verify = function (e) {
          var r = h((e = e || {}));
          if (void 0 === e.signature)
            throw TypeError(
              '"options.signature" must be a node.js Buffer, a Uint8Array, a forge ByteBuffer, or a binary string.'
            );
          var n = h({ message: e.signature, encoding: "binary" });
          if (n.length !== f.constants.SIGN_BYTE_LENGTH)
            throw TypeError(
              '"options.signature" must have a byte length of ' +
                f.constants.SIGN_BYTE_LENGTH
            );
          var a = h({ message: e.publicKey, encoding: "binary" });
          if (a.length !== f.constants.PUBLIC_KEY_BYTE_LENGTH)
            throw TypeError(
              '"options.publicKey" must have a byte length of ' +
                f.constants.PUBLIC_KEY_BYTE_LENGTH
            );
          var s,
            o = new p(f.constants.SIGN_BYTE_LENGTH + r.length),
            c = new p(f.constants.SIGN_BYTE_LENGTH + r.length);
          for (s = 0; s < f.constants.SIGN_BYTE_LENGTH; ++s) o[s] = n[s];
          for (s = 0; s < r.length; ++s)
            o[s + f.constants.SIGN_BYTE_LENGTH] = r[s];
          return (
            (function (e, r, n, a) {
              var s,
                o,
                c,
                u,
                l,
                f,
                h,
                y,
                g,
                v,
                m = new p(32),
                S = [x(), x(), x(), x()],
                I = [x(), x(), x(), x()];
              if (
                n < 64 ||
                ((s = I),
                (o = a),
                (c = x()),
                (u = x()),
                (l = x()),
                (f = x()),
                (h = x()),
                (y = x()),
                (g = x()),
                (D(s[2], _),
                (function (e, r) {
                  var n;
                  for (n = 0; n < 16; ++n)
                    e[n] = r[2 * n] + (r[2 * n + 1] << 8);
                  e[15] &= 32767;
                })(s[1], o),
                K(l, s[1]),
                F(f, l, $),
                O(l, l, s[2]),
                V(f, s[2], f),
                K(h, f),
                K(y, h),
                F(g, y, h),
                F(c, g, l),
                F(c, c, f),
                (function (e, r) {
                  var n,
                    a = x();
                  for (n = 0; n < 16; ++n) a[n] = r[n];
                  for (n = 250; n >= 0; --n) K(a, a), 1 !== n && F(a, a, r);
                  for (n = 0; n < 16; ++n) e[n] = a[n];
                })(c, c),
                F(c, c, l),
                F(c, c, f),
                F(c, c, f),
                F(s[0], c, f),
                K(u, s[0]),
                F(u, u, f),
                N(u, l) && F(s[0], s[0], C),
                K(u, s[0]),
                F(u, u, f),
                N(u, l))
                  ? -1
                  : (k(s[0]) === o[31] >> 7 && O(s[0], d, s[0]),
                    F(s[3], s[0], s[1]),
                    0))
              )
                return -1;
              for (v = 0; v < n; ++v) e[v] = r[v];
              for (v = 0; v < 32; ++v) e[v + 32] = a[v];
              var b = E(e, n);
              if (
                (T(b),
                L(S, I, b),
                U(I, r.subarray(32)),
                B(S, I),
                A(m, S),
                (n -= 64),
                R(r, 0, m, 0))
              ) {
                for (v = 0; v < n; ++v) e[v] = 0;
                return -1;
              }
              for (v = 0; v < n; ++v) e[v] = r[v + 64];
              return n;
            })(c, o, o.length, a) >= 0
          );
        });
      var d = x(),
        _ = x([1]),
        $ = x([
          30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585,
          16505, 36039, 65139, 11119, 27886, 20995,
        ]),
        y = x([
          61785, 9906, 39828, 60374, 45398, 33411, 5274, 224, 53552, 61171,
          33010, 6542, 64743, 22239, 55772, 9222,
        ]),
        g = x([
          54554, 36645, 11616, 51542, 42930, 38181, 51040, 26924, 56412, 64982,
          57905, 49316, 21502, 52590, 14035, 8553,
        ]),
        v = x([
          26200, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214,
          26214, 26214, 26214, 26214, 26214, 26214,
        ]),
        m = new Float64Array([
          237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222,
          20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
        ]),
        C = x([
          41136, 18958, 6951, 50414, 58488, 44335, 6150, 12099, 55207, 15867,
          153, 11085, 57099, 20417, 9344, 11139,
        ]);
      function E(e, r) {
        var n = a.md.sha512.create(),
          s = new l(e);
        n.update(s.getBytes(r), "binary");
        var o = n.digest().getBytes();
        if ("undefined" != typeof Buffer) return Buffer.from(o, "binary");
        for (var c = new p(f.constants.HASH_BYTE_LENGTH), u = 0; u < 64; ++u)
          c[u] = o.charCodeAt(u);
        return c;
      }
      function S(e, r) {
        var n, a, s, o;
        for (a = 63; a >= 32; --a) {
          for (n = 0, s = a - 32, o = a - 12; s < o; ++s)
            (r[s] += n - 16 * r[a] * m[s - (a - 32)]),
              (n = (r[s] + 128) >> 8),
              (r[s] -= 256 * n);
          (r[s] += n), (r[a] = 0);
        }
        for (n = 0, s = 0; s < 32; ++s)
          (r[s] += n - (r[31] >> 4) * m[s]), (n = r[s] >> 8), (r[s] &= 255);
        for (s = 0; s < 32; ++s) r[s] -= n * m[s];
        for (a = 0; a < 32; ++a) (r[a + 1] += r[a] >> 8), (e[a] = 255 & r[a]);
      }
      function T(e) {
        for (var r = new Float64Array(64), n = 0; n < 64; ++n)
          (r[n] = e[n]), (e[n] = 0);
        S(e, r);
      }
      function B(e, r) {
        var n = x(),
          a = x(),
          s = x(),
          o = x(),
          c = x(),
          u = x(),
          l = x(),
          p = x(),
          f = x();
        O(n, e[1], e[0]),
          O(f, r[1], r[0]),
          F(n, n, f),
          V(a, e[0], e[1]),
          V(f, r[0], r[1]),
          F(a, a, f),
          F(s, e[3], r[3]),
          F(s, s, y),
          F(o, e[2], r[2]),
          V(o, o, o),
          O(c, a, n),
          O(u, o, s),
          V(l, o, s),
          V(p, a, n),
          F(e[0], c, u),
          F(e[1], p, l),
          F(e[2], l, u),
          F(e[3], c, p);
      }
      function I(e, r, n) {
        for (var a = 0; a < 4; ++a) P(e[a], r[a], n);
      }
      function A(e, r) {
        var n = x(),
          a = x(),
          s = x();
        !(function (e, r) {
          var n,
            a = x();
          for (n = 0; n < 16; ++n) a[n] = r[n];
          for (n = 253; n >= 0; --n) K(a, a), 2 !== n && 4 !== n && F(a, a, r);
          for (n = 0; n < 16; ++n) e[n] = a[n];
        })(s, r[2]),
          F(n, r[0], s),
          F(a, r[1], s),
          b(e, a),
          (e[31] ^= k(n) << 7);
      }
      function b(e, r) {
        var n,
          a,
          s,
          o = x(),
          c = x();
        for (n = 0; n < 16; ++n) c[n] = r[n];
        for (w(c), w(c), w(c), a = 0; a < 2; ++a) {
          for (o[0] = c[0] - 65517, n = 1; n < 15; ++n)
            (o[n] = c[n] - 65535 - ((o[n - 1] >> 16) & 1)), (o[n - 1] &= 65535);
          (o[15] = c[15] - 32767 - ((o[14] >> 16) & 1)),
            (s = (o[15] >> 16) & 1),
            (o[14] &= 65535),
            P(c, o, 1 - s);
        }
        for (n = 0; n < 16; n++)
          (e[2 * n] = 255 & c[n]), (e[2 * n + 1] = c[n] >> 8);
      }
      function N(e, r) {
        var n = new p(32),
          a = new p(32);
        return b(n, e), b(a, r), R(n, 0, a, 0);
      }
      function R(e, r, n, a) {
        return (function (e, r, n, a, s) {
          var o,
            c = 0;
          for (o = 0; o < 32; ++o) c |= e[r + o] ^ n[a + o];
          return (1 & ((c - 1) >>> 8)) - 1;
        })(e, r, n, a, 32);
      }
      function k(e) {
        var r = new p(32);
        return b(r, e), 1 & r[0];
      }
      function L(e, r, n) {
        var a, s;
        for (
          D(e[0], d), D(e[1], _), D(e[2], _), D(e[3], d), s = 255;
          s >= 0;
          --s
        )
          I(e, r, (a = (n[(s / 8) | 0] >> (7 & s)) & 1)),
            B(r, e),
            B(e, e),
            I(e, r, a);
      }
      function U(e, r) {
        var n = [x(), x(), x(), x()];
        D(n[0], g), D(n[1], v), D(n[2], _), F(n[3], g, v), L(e, n, r);
      }
      function D(e, r) {
        var n;
        for (n = 0; n < 16; n++) e[n] = 0 | r[n];
      }
      function w(e) {
        var r,
          n,
          a = 1;
        for (r = 0; r < 16; ++r)
          (a = Math.floor((n = e[r] + a + 65535) / 65536)),
            (e[r] = n - 65536 * a);
        e[0] += a - 1 + 37 * (a - 1);
      }
      function P(e, r, n) {
        for (var a, s = ~(n - 1), o = 0; o < 16; ++o)
          (a = s & (e[o] ^ r[o])), (e[o] ^= a), (r[o] ^= a);
      }
      function x(e) {
        var r,
          n = new Float64Array(16);
        if (e) for (r = 0; r < e.length; ++r) n[r] = e[r];
        return n;
      }
      function V(e, r, n) {
        for (var a = 0; a < 16; ++a) e[a] = r[a] + n[a];
      }
      function O(e, r, n) {
        for (var a = 0; a < 16; ++a) e[a] = r[a] - n[a];
      }
      function K(e, r) {
        F(e, r, r);
      }
      function F(e, r, n) {
        var a,
          s,
          o = 0,
          c = 0,
          u = 0,
          l = 0,
          p = 0,
          f = 0,
          h = 0,
          d = 0,
          _ = 0,
          $ = 0,
          y = 0,
          g = 0,
          v = 0,
          m = 0,
          C = 0,
          E = 0,
          S = 0,
          T = 0,
          B = 0,
          I = 0,
          A = 0,
          b = 0,
          N = 0,
          R = 0,
          k = 0,
          L = 0,
          U = 0,
          D = 0,
          w = 0,
          P = 0,
          x = 0,
          V = n[0],
          O = n[1],
          K = n[2],
          F = n[3],
          M = n[4],
          H = n[5],
          G = n[6],
          j = n[7],
          q = n[8],
          z = n[9],
          Q = n[10],
          Y = n[11],
          W = n[12],
          X = n[13],
          J = n[14],
          Z = n[15];
        (o += (a = r[0]) * V),
          (c += a * O),
          (u += a * K),
          (l += a * F),
          (p += a * M),
          (f += a * H),
          (h += a * G),
          (d += a * j),
          (_ += a * q),
          ($ += a * z),
          (y += a * Q),
          (g += a * Y),
          (v += a * W),
          (m += a * X),
          (C += a * J),
          (E += a * Z),
          (c += (a = r[1]) * V),
          (u += a * O),
          (l += a * K),
          (p += a * F),
          (f += a * M),
          (h += a * H),
          (d += a * G),
          (_ += a * j),
          ($ += a * q),
          (y += a * z),
          (g += a * Q),
          (v += a * Y),
          (m += a * W),
          (C += a * X),
          (E += a * J),
          (S += a * Z),
          (u += (a = r[2]) * V),
          (l += a * O),
          (p += a * K),
          (f += a * F),
          (h += a * M),
          (d += a * H),
          (_ += a * G),
          ($ += a * j),
          (y += a * q),
          (g += a * z),
          (v += a * Q),
          (m += a * Y),
          (C += a * W),
          (E += a * X),
          (S += a * J),
          (T += a * Z),
          (l += (a = r[3]) * V),
          (p += a * O),
          (f += a * K),
          (h += a * F),
          (d += a * M),
          (_ += a * H),
          ($ += a * G),
          (y += a * j),
          (g += a * q),
          (v += a * z),
          (m += a * Q),
          (C += a * Y),
          (E += a * W),
          (S += a * X),
          (T += a * J),
          (B += a * Z),
          (p += (a = r[4]) * V),
          (f += a * O),
          (h += a * K),
          (d += a * F),
          (_ += a * M),
          ($ += a * H),
          (y += a * G),
          (g += a * j),
          (v += a * q),
          (m += a * z),
          (C += a * Q),
          (E += a * Y),
          (S += a * W),
          (T += a * X),
          (B += a * J),
          (I += a * Z),
          (f += (a = r[5]) * V),
          (h += a * O),
          (d += a * K),
          (_ += a * F),
          ($ += a * M),
          (y += a * H),
          (g += a * G),
          (v += a * j),
          (m += a * q),
          (C += a * z),
          (E += a * Q),
          (S += a * Y),
          (T += a * W),
          (B += a * X),
          (I += a * J),
          (A += a * Z),
          (h += (a = r[6]) * V),
          (d += a * O),
          (_ += a * K),
          ($ += a * F),
          (y += a * M),
          (g += a * H),
          (v += a * G),
          (m += a * j),
          (C += a * q),
          (E += a * z),
          (S += a * Q),
          (T += a * Y),
          (B += a * W),
          (I += a * X),
          (A += a * J),
          (b += a * Z),
          (d += (a = r[7]) * V),
          (_ += a * O),
          ($ += a * K),
          (y += a * F),
          (g += a * M),
          (v += a * H),
          (m += a * G),
          (C += a * j),
          (E += a * q),
          (S += a * z),
          (T += a * Q),
          (B += a * Y),
          (I += a * W),
          (A += a * X),
          (b += a * J),
          (N += a * Z),
          (_ += (a = r[8]) * V),
          ($ += a * O),
          (y += a * K),
          (g += a * F),
          (v += a * M),
          (m += a * H),
          (C += a * G),
          (E += a * j),
          (S += a * q),
          (T += a * z),
          (B += a * Q),
          (I += a * Y),
          (A += a * W),
          (b += a * X),
          (N += a * J),
          (R += a * Z),
          ($ += (a = r[9]) * V),
          (y += a * O),
          (g += a * K),
          (v += a * F),
          (m += a * M),
          (C += a * H),
          (E += a * G),
          (S += a * j),
          (T += a * q),
          (B += a * z),
          (I += a * Q),
          (A += a * Y),
          (b += a * W),
          (N += a * X),
          (R += a * J),
          (k += a * Z),
          (y += (a = r[10]) * V),
          (g += a * O),
          (v += a * K),
          (m += a * F),
          (C += a * M),
          (E += a * H),
          (S += a * G),
          (T += a * j),
          (B += a * q),
          (I += a * z),
          (A += a * Q),
          (b += a * Y),
          (N += a * W),
          (R += a * X),
          (k += a * J),
          (L += a * Z),
          (g += (a = r[11]) * V),
          (v += a * O),
          (m += a * K),
          (C += a * F),
          (E += a * M),
          (S += a * H),
          (T += a * G),
          (B += a * j),
          (I += a * q),
          (A += a * z),
          (b += a * Q),
          (N += a * Y),
          (R += a * W),
          (k += a * X),
          (L += a * J),
          (U += a * Z),
          (v += (a = r[12]) * V),
          (m += a * O),
          (C += a * K),
          (E += a * F),
          (S += a * M),
          (T += a * H),
          (B += a * G),
          (I += a * j),
          (A += a * q),
          (b += a * z),
          (N += a * Q),
          (R += a * Y),
          (k += a * W),
          (L += a * X),
          (U += a * J),
          (D += a * Z),
          (m += (a = r[13]) * V),
          (C += a * O),
          (E += a * K),
          (S += a * F),
          (T += a * M),
          (B += a * H),
          (I += a * G),
          (A += a * j),
          (b += a * q),
          (N += a * z),
          (R += a * Q),
          (k += a * Y),
          (L += a * W),
          (U += a * X),
          (D += a * J),
          (w += a * Z),
          (C += (a = r[14]) * V),
          (E += a * O),
          (S += a * K),
          (T += a * F),
          (B += a * M),
          (I += a * H),
          (A += a * G),
          (b += a * j),
          (N += a * q),
          (R += a * z),
          (k += a * Q),
          (L += a * Y),
          (U += a * W),
          (D += a * X),
          (w += a * J),
          (P += a * Z),
          (E += (a = r[15]) * V),
          (c += 38 * (T += a * K)),
          (u += 38 * (B += a * F)),
          (l += 38 * (I += a * M)),
          (p += 38 * (A += a * H)),
          (f += 38 * (b += a * G)),
          (h += 38 * (N += a * j)),
          (d += 38 * (R += a * q)),
          (_ += 38 * (k += a * z)),
          ($ += 38 * (L += a * Q)),
          (y += 38 * (U += a * Y)),
          (g += 38 * (D += a * W)),
          (v += 38 * (w += a * X)),
          (m += 38 * (P += a * J)),
          (C += 38 * (x += a * Z)),
          (o =
            (a = (o += 38 * (S += a * O)) + (s = 1) + 65535) -
            65536 * (s = Math.floor(a / 65536))),
          (c = (a = c + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (u = (a = u + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (l = (a = l + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (p = (a = p + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (f = (a = f + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (h = (a = h + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (d = (a = d + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (_ = (a = _ + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          ($ = (a = $ + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (y = (a = y + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (g = (a = g + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (v = (a = v + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (m = (a = m + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (C = (a = C + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (E = (a = E + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (o =
            (a = (o += s - 1 + 37 * (s - 1)) + (s = 1) + 65535) -
            65536 * (s = Math.floor(a / 65536))),
          (c = (a = c + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (u = (a = u + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (l = (a = l + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (p = (a = p + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (f = (a = f + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (h = (a = h + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (d = (a = d + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (_ = (a = _ + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          ($ = (a = $ + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (y = (a = y + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (g = (a = g + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (v = (a = v + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (m = (a = m + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (C = (a = C + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (E = (a = E + s + 65535) - 65536 * (s = Math.floor(a / 65536))),
          (o += s - 1 + 37 * (s - 1)),
          (e[0] = o),
          (e[1] = c),
          (e[2] = u),
          (e[3] = l),
          (e[4] = p),
          (e[5] = f),
          (e[6] = h),
          (e[7] = d),
          (e[8] = _),
          (e[9] = $),
          (e[10] = y),
          (e[11] = g),
          (e[12] = v),
          (e[13] = m),
          (e[14] = C),
          (e[15] = E);
      }
    },
    function (e, r, n) {
      var a = n(0);
      n(3);
      var s = a.asn1;
      (r.privateKeyValidator = {
        name: "PrivateKeyInfo",
        tagClass: s.Class.UNIVERSAL,
        type: s.Type.SEQUENCE,
        constructed: !0,
        value: [
          {
            name: "PrivateKeyInfo.version",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.INTEGER,
            constructed: !1,
            capture: "privateKeyVersion",
          },
          {
            name: "PrivateKeyInfo.privateKeyAlgorithm",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.SEQUENCE,
            constructed: !0,
            value: [
              {
                name: "AlgorithmIdentifier.algorithm",
                tagClass: s.Class.UNIVERSAL,
                type: s.Type.OID,
                constructed: !1,
                capture: "privateKeyOid",
              },
            ],
          },
          {
            name: "PrivateKeyInfo",
            tagClass: s.Class.UNIVERSAL,
            type: s.Type.OCTETSTRING,
            constructed: !1,
            capture: "privateKey",
          },
        ],
      }),
        (r.publicKeyValidator = {
          name: "SubjectPublicKeyInfo",
          tagClass: s.Class.UNIVERSAL,
          type: s.Type.SEQUENCE,
          constructed: !0,
          captureAsn1: "subjectPublicKeyInfo",
          value: [
            {
              name: "SubjectPublicKeyInfo.AlgorithmIdentifier",
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.SEQUENCE,
              constructed: !0,
              value: [
                {
                  name: "AlgorithmIdentifier.algorithm",
                  tagClass: s.Class.UNIVERSAL,
                  type: s.Type.OID,
                  constructed: !1,
                  capture: "publicKeyOid",
                },
              ],
            },
            {
              tagClass: s.Class.UNIVERSAL,
              type: s.Type.BITSTRING,
              constructed: !1,
              composed: !0,
              captureBitStringValue: "ed25519PublicKey",
            },
          ],
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(1), n(2), n(12), (e.exports = a.kem = a.kem || {});
      var s = a.jsbn.BigInteger;
      function o(e, r, n, s) {
        e.generate = function (e, o) {
          for (
            var c = new a.util.ByteBuffer(),
              u = Math.ceil(o / s) + n,
              l = new a.util.ByteBuffer(),
              p = n;
            p < u;
            ++p
          ) {
            l.putInt32(p), r.start(), r.update(e + l.getBytes());
            var f = r.digest();
            c.putBytes(f.getBytes(s));
          }
          return c.truncate(c.length() - o), c.getBytes();
        };
      }
      (a.kem.rsa = {}),
        (a.kem.rsa.create = function (e, r) {
          var n = (r = r || {}).prng || a.random;
          return {
            encrypt: function (r, o) {
              var c,
                u = Math.ceil(r.n.bitLength() / 8);
              do c = new s(a.util.bytesToHex(n.getBytesSync(u)), 16).mod(r.n);
              while (0 >= c.compareTo(s.ONE));
              var l = u - (c = a.util.hexToBytes(c.toString(16))).length;
              return (
                l > 0 && (c = a.util.fillString("\0", l) + c),
                { encapsulation: r.encrypt(c, "NONE"), key: e.generate(c, o) }
              );
            },
            decrypt: function (r, n, a) {
              var s = r.decrypt(n, "NONE");
              return e.generate(s, a);
            },
          };
        }),
        (a.kem.kdf1 = function (e, r) {
          o(this, e, 0, r || e.digestLength);
        }),
        (a.kem.kdf2 = function (e, r) {
          o(this, e, 1, r || e.digestLength);
        });
    },
    function (e, r, n) {
      var a,
        s = n(0);
      n(1),
        (e.exports = s.log = s.log || {}),
        (s.log.levels = [
          "none",
          "error",
          "warning",
          "info",
          "debug",
          "verbose",
          "max",
        ]);
      var o = {},
        c = [],
        u = null;
      (s.log.LEVEL_LOCKED = 2),
        (s.log.NO_LEVEL_CHECK = 4),
        (s.log.INTERPOLATE = 8);
      for (var l = 0; l < s.log.levels.length; ++l) {
        var p = s.log.levels[l];
        o[p] = { index: l, name: p.toUpperCase() };
      }
      (s.log.logMessage = function (e) {
        for (var r = o[e.level].index, n = 0; n < c.length; ++n) {
          var a = c[n];
          a.flags & s.log.NO_LEVEL_CHECK
            ? a.f(e)
            : r <= o[a.level].index && a.f(a, e);
        }
      }),
        (s.log.prepareStandard = function (e) {
          "standard" in e ||
            (e.standard =
              o[e.level].name + " [" + e.category + "] " + e.message);
        }),
        (s.log.prepareFull = function (e) {
          if (!("full" in e)) {
            var r = [e.message];
            (r = r.concat([])), (e.full = s.util.format.apply(this, r));
          }
        }),
        (s.log.prepareStandardFull = function (e) {
          "standardFull" in e ||
            (s.log.prepareStandard(e), (e.standardFull = e.standard));
        });
      var f = ["error", "warning", "info", "debug", "verbose"];
      for (l = 0; l < f.length; ++l)
        !(function (e) {
          s.log[e] = function (r, n) {
            var a = Array.prototype.slice.call(arguments).slice(2),
              o = {
                timestamp: new Date(),
                level: e,
                category: r,
                message: n,
                arguments: a,
              };
            s.log.logMessage(o);
          };
        })(f[l]);
      if (
        ((s.log.makeLogger = function (e) {
          var r = { flags: 0, f: e };
          return s.log.setLevel(r, "none"), r;
        }),
        (s.log.setLevel = function (e, r) {
          var n = !1;
          if (e && !(e.flags & s.log.LEVEL_LOCKED)) {
            for (var a = 0; a < s.log.levels.length; ++a)
              if (r == s.log.levels[a]) {
                (e.level = r), (n = !0);
                break;
              }
          }
          return n;
        }),
        (s.log.lock = function (e, r) {
          void 0 === r || r
            ? (e.flags |= s.log.LEVEL_LOCKED)
            : (e.flags &= ~s.log.LEVEL_LOCKED);
        }),
        (s.log.addLogger = function (e) {
          c.push(e);
        }),
        "undefined" != typeof console && "log" in console)
      ) {
        if (console.error && console.warn && console.info && console.debug) {
          var h = {
              error: console.error,
              warning: console.warn,
              info: console.info,
              debug: console.debug,
              verbose: console.debug,
            },
            d = function (e, r) {
              s.log.prepareStandard(r);
              var n = h[r.level],
                a = [r.standard];
              (a = a.concat(r.arguments.slice())), n.apply(console, a);
            };
          a = s.log.makeLogger(d);
        } else
          (d = function (e, r) {
            s.log.prepareStandardFull(r), console.log(r.standardFull);
          }),
            (a = s.log.makeLogger(d));
        s.log.setLevel(a, "debug"), s.log.addLogger(a), (u = a);
      } else console = { log: function () {} };
      s.log.consoleLogger = u;
    },
    function (e, r, n) {
      (e.exports = n(4)), n(14), n(9), n(23), n(31);
    },
    function (e, r, n) {
      var a = n(0);
      n(5), n(3), n(10), n(6), n(7), n(29), n(2), n(1), n(17);
      var s = a.asn1,
        o = (e.exports = a.pkcs7 = a.pkcs7 || {});
      function c(e) {
        var r = {},
          n = [];
        if (!s.validate(e, o.asn1.recipientInfoValidator, r, n)) {
          var c = Error(
            "Cannot read PKCS#7 RecipientInfo. ASN.1 object is not an PKCS#7 RecipientInfo."
          );
          throw ((c.errors = n), c);
        }
        return {
          version: r.version.charCodeAt(0),
          issuer: a.pki.RDNAttributesAsArray(r.issuer),
          serialNumber: a.util.createBuffer(r.serial).toHex(),
          encryptedContent: {
            algorithm: s.derToOid(r.encAlgorithm),
            parameter: r.encParameter ? r.encParameter.value : void 0,
            content: r.encKey,
          },
        };
      }
      function u(e) {
        var r = s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
          s.create(
            s.Class.UNIVERSAL,
            s.Type.INTEGER,
            !1,
            s.integerToDer(e.version).getBytes()
          ),
          s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
            a.pki.distinguishedNameToAsn1({ attributes: e.issuer }),
            s.create(
              s.Class.UNIVERSAL,
              s.Type.INTEGER,
              !1,
              a.util.hexToBytes(e.serialNumber)
            ),
          ]),
          s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
            s.create(
              s.Class.UNIVERSAL,
              s.Type.OID,
              !1,
              s.oidToDer(e.digestAlgorithm).getBytes()
            ),
            s.create(s.Class.UNIVERSAL, s.Type.NULL, !1, ""),
          ]),
        ]);
        if (
          (e.authenticatedAttributesAsn1 &&
            r.value.push(e.authenticatedAttributesAsn1),
          r.value.push(
            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
              s.create(
                s.Class.UNIVERSAL,
                s.Type.OID,
                !1,
                s.oidToDer(e.signatureAlgorithm).getBytes()
              ),
              s.create(s.Class.UNIVERSAL, s.Type.NULL, !1, ""),
            ])
          ),
          r.value.push(
            s.create(s.Class.UNIVERSAL, s.Type.OCTETSTRING, !1, e.signature)
          ),
          e.unauthenticatedAttributes.length > 0)
        ) {
          for (
            var n = s.create(s.Class.CONTEXT_SPECIFIC, 1, !0, []), o = 0;
            o < e.unauthenticatedAttributes.length;
            ++o
          ) {
            var c = e.unauthenticatedAttributes[o];
            n.values.push(l(c));
          }
          r.value.push(n);
        }
        return r;
      }
      function l(e) {
        var r;
        if (e.type === a.pki.oids.contentType)
          r = s.create(
            s.Class.UNIVERSAL,
            s.Type.OID,
            !1,
            s.oidToDer(e.value).getBytes()
          );
        else if (e.type === a.pki.oids.messageDigest)
          r = s.create(
            s.Class.UNIVERSAL,
            s.Type.OCTETSTRING,
            !1,
            e.value.bytes()
          );
        else if (e.type === a.pki.oids.signingTime) {
          var n = new Date("1950-01-01T00:00:00Z"),
            o = new Date("2050-01-01T00:00:00Z"),
            c = e.value;
          if ("string" == typeof c) {
            var u = Date.parse(c);
            c = isNaN(u)
              ? 13 === c.length
                ? s.utcTimeToDate(c)
                : s.generalizedTimeToDate(c)
              : new Date(u);
          }
          r =
            c >= n && c < o
              ? s.create(
                  s.Class.UNIVERSAL,
                  s.Type.UTCTIME,
                  !1,
                  s.dateToUtcTime(c)
                )
              : s.create(
                  s.Class.UNIVERSAL,
                  s.Type.GENERALIZEDTIME,
                  !1,
                  s.dateToGeneralizedTime(c)
                );
        }
        return s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
          s.create(
            s.Class.UNIVERSAL,
            s.Type.OID,
            !1,
            s.oidToDer(e.type).getBytes()
          ),
          s.create(s.Class.UNIVERSAL, s.Type.SET, !0, [r]),
        ]);
      }
      function p(e, r, n) {
        var o = {};
        if (!s.validate(r, n, o, [])) {
          var c = Error(
            "Cannot read PKCS#7 message. ASN.1 object is not a supported PKCS#7 message."
          );
          throw ((c.errors = c), c);
        }
        if (s.derToOid(o.contentType) !== a.pki.oids.data)
          throw Error(
            "Unsupported PKCS#7 message. Only wrapped ContentType Data supported."
          );
        if (o.encryptedContent) {
          var u = "";
          if (a.util.isArray(o.encryptedContent))
            for (var l = 0; l < o.encryptedContent.length; ++l) {
              if (o.encryptedContent[l].type !== s.Type.OCTETSTRING)
                throw Error(
                  "Malformed PKCS#7 message, expecting encrypted content constructed of only OCTET STRING objects."
                );
              u += o.encryptedContent[l].value;
            }
          else u = o.encryptedContent;
          e.encryptedContent = {
            algorithm: s.derToOid(o.encAlgorithm),
            parameter: a.util.createBuffer(o.encParameter.value),
            content: a.util.createBuffer(u),
          };
        }
        if (o.content) {
          if (((u = ""), a.util.isArray(o.content)))
            for (l = 0; l < o.content.length; ++l) {
              if (o.content[l].type !== s.Type.OCTETSTRING)
                throw Error(
                  "Malformed PKCS#7 message, expecting content constructed of only OCTET STRING objects."
                );
              u += o.content[l].value;
            }
          else u = o.content;
          e.content = a.util.createBuffer(u);
        }
        return (e.version = o.version.charCodeAt(0)), (e.rawCapture = o), o;
      }
      function f(e) {
        if (void 0 === e.encryptedContent.key)
          throw Error("Symmetric key not available.");
        if (void 0 === e.content) {
          var r;
          switch (e.encryptedContent.algorithm) {
            case a.pki.oids["aes128-CBC"]:
            case a.pki.oids["aes192-CBC"]:
            case a.pki.oids["aes256-CBC"]:
              r = a.aes.createDecryptionCipher(e.encryptedContent.key);
              break;
            case a.pki.oids.desCBC:
            case a.pki.oids["des-EDE3-CBC"]:
              r = a.des.createDecryptionCipher(e.encryptedContent.key);
              break;
            default:
              throw Error(
                "Unsupported symmetric cipher, OID " +
                  e.encryptedContent.algorithm
              );
          }
          if (
            (r.start(e.encryptedContent.parameter),
            r.update(e.encryptedContent.content),
            !r.finish())
          )
            throw Error("Symmetric decryption failed.");
          e.content = r.output;
        }
      }
      (o.messageFromPem = function (e) {
        var r = a.pem.decode(e)[0];
        if ("PKCS7" !== r.type) {
          var n = Error(
            'Could not convert PKCS#7 message from PEM; PEM header type is not "PKCS#7".'
          );
          throw ((n.headerType = r.type), n);
        }
        if (r.procType && "ENCRYPTED" === r.procType.type)
          throw Error(
            "Could not convert PKCS#7 message from PEM; PEM is encrypted."
          );
        var c = s.fromDer(r.body);
        return o.messageFromAsn1(c);
      }),
        (o.messageToPem = function (e, r) {
          var n = { type: "PKCS7", body: s.toDer(e.toAsn1()).getBytes() };
          return a.pem.encode(n, { maxline: r });
        }),
        (o.messageFromAsn1 = function (e) {
          var r = {},
            n = [];
          if (!s.validate(e, o.asn1.contentInfoValidator, r, n)) {
            var c = Error(
              "Cannot read PKCS#7 message. ASN.1 object is not an PKCS#7 ContentInfo."
            );
            throw ((c.errors = n), c);
          }
          var u,
            l = s.derToOid(r.contentType);
          switch (l) {
            case a.pki.oids.envelopedData:
              u = o.createEnvelopedData();
              break;
            case a.pki.oids.encryptedData:
              u = o.createEncryptedData();
              break;
            case a.pki.oids.signedData:
              u = o.createSignedData();
              break;
            default:
              throw Error(
                "Cannot read PKCS#7 message. ContentType with OID " +
                  l +
                  " is not (yet) supported."
              );
          }
          return u.fromAsn1(r.content.value[0]), u;
        }),
        (o.createSignedData = function () {
          var e = null;
          return (e = {
            type: a.pki.oids.signedData,
            version: 1,
            certificates: [],
            crls: [],
            signers: [],
            digestAlgorithmIdentifiers: [],
            contentInfo: null,
            signerInfos: [],
            fromAsn1: function (r) {
              if (
                (p(e, r, o.asn1.signedDataValidator),
                (e.certificates = []),
                (e.crls = []),
                (e.digestAlgorithmIdentifiers = []),
                (e.contentInfo = null),
                (e.signerInfos = []),
                e.rawCapture.certificates)
              )
                for (
                  var n = e.rawCapture.certificates.value, s = 0;
                  s < n.length;
                  ++s
                )
                  e.certificates.push(a.pki.certificateFromAsn1(n[s]));
            },
            toAsn1: function () {
              e.contentInfo || e.sign();
              for (var r = [], n = 0; n < e.certificates.length; ++n)
                r.push(a.pki.certificateToAsn1(e.certificates[n]));
              var o = [],
                c = s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                  s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.INTEGER,
                      !1,
                      s.integerToDer(e.version).getBytes()
                    ),
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.SET,
                      !0,
                      e.digestAlgorithmIdentifiers
                    ),
                    e.contentInfo,
                  ]),
                ]);
              return (
                r.length > 0 &&
                  c.value[0].value.push(
                    s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, r)
                  ),
                o.length > 0 &&
                  c.value[0].value.push(
                    s.create(s.Class.CONTEXT_SPECIFIC, 1, !0, o)
                  ),
                c.value[0].value.push(
                  s.create(s.Class.UNIVERSAL, s.Type.SET, !0, e.signerInfos)
                ),
                s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                  s.create(
                    s.Class.UNIVERSAL,
                    s.Type.OID,
                    !1,
                    s.oidToDer(e.type).getBytes()
                  ),
                  c,
                ])
              );
            },
            addSigner: function (r) {
              var n = r.issuer,
                s = r.serialNumber;
              if (r.certificate) {
                var o = r.certificate;
                "string" == typeof o && (o = a.pki.certificateFromPem(o)),
                  (n = o.issuer.attributes),
                  (s = o.serialNumber);
              }
              var c = r.key;
              if (!c)
                throw Error(
                  "Could not add PKCS#7 signer; no private key specified."
                );
              "string" == typeof c && (c = a.pki.privateKeyFromPem(c));
              var u = r.digestAlgorithm || a.pki.oids.sha1;
              switch (u) {
                case a.pki.oids.sha1:
                case a.pki.oids.sha256:
                case a.pki.oids.sha384:
                case a.pki.oids.sha512:
                case a.pki.oids.md5:
                  break;
                default:
                  throw Error(
                    "Could not add PKCS#7 signer; unknown message digest algorithm: " +
                      u
                  );
              }
              var l = r.authenticatedAttributes || [];
              if (l.length > 0) {
                for (var p = !1, f = !1, h = 0; h < l.length; ++h) {
                  var d = l[h];
                  if (p || d.type !== a.pki.oids.contentType) {
                    if (f || d.type !== a.pki.oids.messageDigest);
                    else if (((f = !0), p)) break;
                  } else if (((p = !0), f)) break;
                }
                if (!p || !f)
                  throw Error(
                    "Invalid signer.authenticatedAttributes. If signer.authenticatedAttributes is specified, then it must contain at least two attributes, PKCS #9 content-type and PKCS #9 message-digest."
                  );
              }
              e.signers.push({
                key: c,
                version: 1,
                issuer: n,
                serialNumber: s,
                digestAlgorithm: u,
                signatureAlgorithm: a.pki.oids.rsaEncryption,
                signature: null,
                authenticatedAttributes: l,
                unauthenticatedAttributes: [],
              });
            },
            sign: function (r) {
              var n;
              (r = r || {}),
                ("object" != typeof e.content || null === e.contentInfo) &&
                  ((e.contentInfo = s.create(
                    s.Class.UNIVERSAL,
                    s.Type.SEQUENCE,
                    !0,
                    [
                      s.create(
                        s.Class.UNIVERSAL,
                        s.Type.OID,
                        !1,
                        s.oidToDer(a.pki.oids.data).getBytes()
                      ),
                    ]
                  )),
                  "content" in e &&
                    (e.content instanceof a.util.ByteBuffer
                      ? (n = e.content.bytes())
                      : "string" == typeof e.content &&
                        (n = a.util.encodeUtf8(e.content)),
                    r.detached
                      ? (e.detachedContent = s.create(
                          s.Class.UNIVERSAL,
                          s.Type.OCTETSTRING,
                          !1,
                          n
                        ))
                      : e.contentInfo.value.push(
                          s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                            s.create(
                              s.Class.UNIVERSAL,
                              s.Type.OCTETSTRING,
                              !1,
                              n
                            ),
                          ])
                        ))),
                0 !== e.signers.length &&
                  (function (r) {
                    if (
                      !(n = e.detachedContent
                        ? e.detachedContent
                        : (n = e.contentInfo.value[1]).value[0])
                    )
                      throw Error(
                        "Could not sign PKCS#7 message; there is no content to sign."
                      );
                    var n,
                      o = s.derToOid(e.contentInfo.value[0].value),
                      c = s.toDer(n);
                    for (var p in (c.getByte(),
                    s.getBerValueLength(c),
                    (c = c.getBytes()),
                    r))
                      r[p].start().update(c);
                    for (var f = new Date(), h = 0; h < e.signers.length; ++h) {
                      var d = e.signers[h];
                      if (0 === d.authenticatedAttributes.length) {
                        if (o !== a.pki.oids.data)
                          throw Error(
                            "Invalid signer; authenticatedAttributes must be present when the ContentInfo content type is not PKCS#7 Data."
                          );
                      } else {
                        d.authenticatedAttributesAsn1 = s.create(
                          s.Class.CONTEXT_SPECIFIC,
                          0,
                          !0,
                          []
                        );
                        for (
                          var _ = s.create(
                              s.Class.UNIVERSAL,
                              s.Type.SET,
                              !0,
                              []
                            ),
                            $ = 0;
                          $ < d.authenticatedAttributes.length;
                          ++$
                        ) {
                          var y = d.authenticatedAttributes[$];
                          y.type === a.pki.oids.messageDigest
                            ? (y.value = r[d.digestAlgorithm].digest())
                            : y.type === a.pki.oids.signingTime &&
                              (y.value || (y.value = f)),
                            _.value.push(l(y)),
                            d.authenticatedAttributesAsn1.value.push(l(y));
                        }
                        (c = s.toDer(_).getBytes()), d.md.start().update(c);
                      }
                      d.signature = d.key.sign(d.md, "RSASSA-PKCS1-V1_5");
                    }
                    e.signerInfos = (function (e) {
                      for (var r = [], n = 0; n < e.length; ++n)
                        r.push(u(e[n]));
                      return r;
                    })(e.signers);
                  })(
                    (function () {
                      for (var r = {}, n = 0; n < e.signers.length; ++n) {
                        var o = e.signers[n];
                        (c = o.digestAlgorithm) in r ||
                          (r[c] = a.md[a.pki.oids[c]].create()),
                          0 === o.authenticatedAttributes.length
                            ? (o.md = r[c])
                            : (o.md = a.md[a.pki.oids[c]].create());
                      }
                      for (var c in ((e.digestAlgorithmIdentifiers = []), r))
                        e.digestAlgorithmIdentifiers.push(
                          s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                            s.create(
                              s.Class.UNIVERSAL,
                              s.Type.OID,
                              !1,
                              s.oidToDer(c).getBytes()
                            ),
                            s.create(s.Class.UNIVERSAL, s.Type.NULL, !1, ""),
                          ])
                        );
                      return r;
                    })()
                  );
            },
            verify: function () {
              throw Error("PKCS#7 signature verification not yet implemented.");
            },
            addCertificate: function (r) {
              "string" == typeof r && (r = a.pki.certificateFromPem(r)),
                e.certificates.push(r);
            },
            addCertificateRevokationList: function (e) {
              throw Error("PKCS#7 CRL support not yet implemented.");
            },
          });
        }),
        (o.createEncryptedData = function () {
          var e = null;
          return (e = {
            type: a.pki.oids.encryptedData,
            version: 0,
            encryptedContent: { algorithm: a.pki.oids["aes256-CBC"] },
            fromAsn1: function (r) {
              p(e, r, o.asn1.encryptedDataValidator);
            },
            decrypt: function (r) {
              void 0 !== r && (e.encryptedContent.key = r), f(e);
            },
          });
        }),
        (o.createEnvelopedData = function () {
          var e = null;
          return (e = {
            type: a.pki.oids.envelopedData,
            version: 0,
            recipients: [],
            encryptedContent: { algorithm: a.pki.oids["aes256-CBC"] },
            fromAsn1: function (r) {
              var n = p(e, r, o.asn1.envelopedDataValidator);
              e.recipients = (function (e) {
                for (var r = [], n = 0; n < e.length; ++n) r.push(c(e[n]));
                return r;
              })(n.recipientInfos.value);
            },
            toAsn1: function () {
              var r;
              return s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                s.create(
                  s.Class.UNIVERSAL,
                  s.Type.OID,
                  !1,
                  s.oidToDer(e.type).getBytes()
                ),
                s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                  s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.INTEGER,
                      !1,
                      s.integerToDer(e.version).getBytes()
                    ),
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.SET,
                      !0,
                      (function e(r) {
                        for (var n, o = [], c = 0; c < r.length; ++c)
                          o.push(
                            ((n = r[c]),
                            s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                              s.create(
                                s.Class.UNIVERSAL,
                                s.Type.INTEGER,
                                !1,
                                s.integerToDer(n.version).getBytes()
                              ),
                              s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                                a.pki.distinguishedNameToAsn1({
                                  attributes: n.issuer,
                                }),
                                s.create(
                                  s.Class.UNIVERSAL,
                                  s.Type.INTEGER,
                                  !1,
                                  a.util.hexToBytes(n.serialNumber)
                                ),
                              ]),
                              s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                                s.create(
                                  s.Class.UNIVERSAL,
                                  s.Type.OID,
                                  !1,
                                  s
                                    .oidToDer(n.encryptedContent.algorithm)
                                    .getBytes()
                                ),
                                s.create(
                                  s.Class.UNIVERSAL,
                                  s.Type.NULL,
                                  !1,
                                  ""
                                ),
                              ]),
                              s.create(
                                s.Class.UNIVERSAL,
                                s.Type.OCTETSTRING,
                                !1,
                                n.encryptedContent.content
                              ),
                            ]))
                          );
                        return o;
                      })(e.recipients)
                    ),
                    s.create(
                      s.Class.UNIVERSAL,
                      s.Type.SEQUENCE,
                      !0,
                      ((r = e.encryptedContent),
                      [
                        s.create(
                          s.Class.UNIVERSAL,
                          s.Type.OID,
                          !1,
                          s.oidToDer(a.pki.oids.data).getBytes()
                        ),
                        s.create(s.Class.UNIVERSAL, s.Type.SEQUENCE, !0, [
                          s.create(
                            s.Class.UNIVERSAL,
                            s.Type.OID,
                            !1,
                            s.oidToDer(r.algorithm).getBytes()
                          ),
                          r.parameter
                            ? s.create(
                                s.Class.UNIVERSAL,
                                s.Type.OCTETSTRING,
                                !1,
                                r.parameter.getBytes()
                              )
                            : void 0,
                        ]),
                        s.create(s.Class.CONTEXT_SPECIFIC, 0, !0, [
                          s.create(
                            s.Class.UNIVERSAL,
                            s.Type.OCTETSTRING,
                            !1,
                            r.content.getBytes()
                          ),
                        ]),
                      ])
                    ),
                  ]),
                ]),
              ]);
            },
            findRecipient: function (r) {
              for (
                var n = r.issuer.attributes, a = 0;
                a < e.recipients.length;
                ++a
              ) {
                var s = e.recipients[a],
                  o = s.issuer;
                if (
                  s.serialNumber === r.serialNumber &&
                  o.length === n.length
                ) {
                  for (var c = !0, u = 0; u < n.length; ++u)
                    if (o[u].type !== n[u].type || o[u].value !== n[u].value) {
                      c = !1;
                      break;
                    }
                  if (c) return s;
                }
              }
              return null;
            },
            decrypt: function (r, n) {
              if (
                void 0 === e.encryptedContent.key &&
                void 0 !== r &&
                void 0 !== n
              )
                switch (r.encryptedContent.algorithm) {
                  case a.pki.oids.rsaEncryption:
                  case a.pki.oids.desCBC:
                    var s = n.decrypt(r.encryptedContent.content);
                    e.encryptedContent.key = a.util.createBuffer(s);
                    break;
                  default:
                    throw Error(
                      "Unsupported asymmetric cipher, OID " +
                        r.encryptedContent.algorithm
                    );
                }
              f(e);
            },
            addRecipient: function (r) {
              e.recipients.push({
                version: 0,
                issuer: r.issuer.attributes,
                serialNumber: r.serialNumber,
                encryptedContent: {
                  algorithm: a.pki.oids.rsaEncryption,
                  key: r.publicKey,
                },
              });
            },
            encrypt: function (r, n) {
              if (void 0 === e.encryptedContent.content) {
                switch (
                  ((n = n || e.encryptedContent.algorithm),
                  (r = r || e.encryptedContent.key),
                  n)
                ) {
                  case a.pki.oids["aes128-CBC"]:
                    (s = 16), (o = 16), (c = a.aes.createEncryptionCipher);
                    break;
                  case a.pki.oids["aes192-CBC"]:
                    (s = 24), (o = 16), (c = a.aes.createEncryptionCipher);
                    break;
                  case a.pki.oids["aes256-CBC"]:
                    (s = 32), (o = 16), (c = a.aes.createEncryptionCipher);
                    break;
                  case a.pki.oids["des-EDE3-CBC"]:
                    (s = 24), (o = 8), (c = a.des.createEncryptionCipher);
                    break;
                  default:
                    throw Error("Unsupported symmetric cipher, OID " + n);
                }
                if (void 0 === r) r = a.util.createBuffer(a.random.getBytes(s));
                else if (r.length() != s)
                  throw Error(
                    "Symmetric key has wrong length; got " +
                      r.length() +
                      " bytes, expected " +
                      s +
                      "."
                  );
                (e.encryptedContent.algorithm = n),
                  (e.encryptedContent.key = r),
                  (e.encryptedContent.parameter = a.util.createBuffer(
                    a.random.getBytes(o)
                  ));
                var s,
                  o,
                  c,
                  u = c(r);
                if (
                  (u.start(e.encryptedContent.parameter.copy()),
                  u.update(e.content),
                  !u.finish())
                )
                  throw Error("Symmetric encryption failed.");
                e.encryptedContent.content = u.output;
              }
              for (var l = 0; l < e.recipients.length; ++l) {
                var p = e.recipients[l];
                if (void 0 === p.encryptedContent.content) {
                  if (p.encryptedContent.algorithm === a.pki.oids.rsaEncryption)
                    p.encryptedContent.content = p.encryptedContent.key.encrypt(
                      e.encryptedContent.key.data
                    );
                  else
                    throw Error(
                      "Unsupported asymmetric cipher, OID " +
                        p.encryptedContent.algorithm
                    );
                }
              }
            },
          });
        });
    },
    function (e, r, n) {
      var a = n(0);
      n(5), n(8), n(14), n(9), n(1);
      var s = (e.exports = a.ssh = a.ssh || {});
      function o(e, r) {
        var n = r.toString(16);
        n[0] >= "8" && (n = "00" + n);
        var s = a.util.hexToBytes(n);
        e.putInt32(s.length), e.putBytes(s);
      }
      function c(e, r) {
        e.putInt32(r.length), e.putString(r);
      }
      function u() {
        for (
          var e = a.md.sha1.create(), r = arguments.length, n = 0;
          n < r;
          ++n
        )
          e.update(arguments[n]);
        return e.digest();
      }
      (s.privateKeyToPutty = function (e, r, n) {
        var s = "" === (r = r || "") ? "none" : "aes256-cbc",
          l = "PuTTY-User-Key-File-2: ssh-rsa\r\n";
        (l += "Encryption: " + s + "\r\n"),
          (l += "Comment: " + (n = n || "") + "\r\n");
        var p = a.util.createBuffer();
        c(p, "ssh-rsa"), o(p, e.e), o(p, e.n);
        var f = a.util.encode64(p.bytes(), 64),
          h = Math.floor(f.length / 66) + 1;
        (l += "Public-Lines: " + h + "\r\n"), (l += f);
        var d,
          _ = a.util.createBuffer();
        if ((o(_, e.d), o(_, e.p), o(_, e.q), o(_, e.qInv), r)) {
          var $ = _.length() + 16 - 1;
          $ -= $ % 16;
          var y = u(_.bytes());
          y.truncate(y.length() - $ + _.length()), _.putBuffer(y);
          var g = a.util.createBuffer();
          g.putBuffer(u("\0\0\0\0", r)), g.putBuffer(u("\0\0\0\x01", r));
          var v = a.aes.createEncryptionCipher(g.truncate(8), "CBC");
          v.start(a.util.createBuffer().fillWithByte(0, 16)),
            v.update(_.copy()),
            v.finish();
          var m = v.output;
          m.truncate(16), (d = a.util.encode64(m.bytes(), 64));
        } else d = a.util.encode64(_.bytes(), 64);
        (l +=
          "\r\nPrivate-Lines: " + (h = Math.floor(d.length / 66) + 1) + "\r\n"),
          (l += d);
        var C = u("putty-private-key-file-mac-key", r),
          E = a.util.createBuffer();
        c(E, "ssh-rsa"),
          c(E, s),
          c(E, n),
          E.putInt32(p.length()),
          E.putBuffer(p),
          E.putInt32(_.length()),
          E.putBuffer(_);
        var S = a.hmac.create();
        return (
          S.start("sha1", C),
          S.update(E.bytes()),
          (l += "\r\nPrivate-MAC: " + S.digest().toHex() + "\r\n")
        );
      }),
        (s.publicKeyToOpenSSH = function (e, r) {
          r = r || "";
          var n = a.util.createBuffer();
          return (
            c(n, "ssh-rsa"),
            o(n, e.e),
            o(n, e.n),
            "ssh-rsa " + a.util.encode64(n.bytes()) + " " + r
          );
        }),
        (s.privateKeyToOpenSSH = function (e, r) {
          return r
            ? a.pki.encryptRsaPrivateKey(e, r, {
                legacy: !0,
                algorithm: "aes128",
              })
            : a.pki.privateKeyToPem(e);
        }),
        (s.getPublicKeyFingerprint = function (e, r) {
          var n = (r = r || {}).md || a.md.md5.create(),
            s = a.util.createBuffer();
          c(s, "ssh-rsa"),
            o(s, e.e),
            o(s, e.n),
            n.start(),
            n.update(s.getBytes());
          var u = n.digest();
          if ("hex" === r.encoding) {
            var l = u.toHex();
            return r.delimiter ? l.match(/.{2}/g).join(r.delimiter) : l;
          }
          if ("binary" === r.encoding) return u.getBytes();
          if (r.encoding) throw Error('Unknown encoding "' + r.encoding + '".');
          return u;
        });
    },
  ]);
});
var rng_state,
  rng_pool,
  rng_pptr,
  t,
  CryptoJS =
    CryptoJS ||
    (function (e, r) {
      var n =
          Object.create ||
          (function () {
            function e() {}
            return function (r) {
              var n;
              return (e.prototype = r), (n = new e()), (e.prototype = null), n;
            };
          })(),
        a = {},
        s = (a.lib = {}),
        o = (s.Base = {
          extend: function (e) {
            var r = n(this);
            return (
              e && r.mixIn(e),
              (r.hasOwnProperty("init") && this.init !== r.init) ||
                (r.init = function () {
                  r.$super.init.apply(this, arguments);
                }),
              (r.init.prototype = r),
              (r.$super = this),
              r
            );
          },
          create: function () {
            var e = this.extend();
            return e.init.apply(e, arguments), e;
          },
          init: function () {},
          mixIn: function (e) {
            for (var r in e) e.hasOwnProperty(r) && (this[r] = e[r]);
            e.hasOwnProperty("toString") && (this.toString = e.toString);
          },
          clone: function () {
            return this.init.prototype.extend(this);
          },
        }),
        c = (s.WordArray = o.extend({
          init: function (e, r) {
            (e = this.words = e || []),
              void 0 != r
                ? (this.sigBytes = r)
                : (this.sigBytes = 4 * e.length);
          },
          toString: function (e) {
            return (e || l).stringify(this);
          },
          concat: function (e) {
            var r = this.words,
              n = e.words,
              a = this.sigBytes,
              s = e.sigBytes;
            if ((this.clamp(), a % 4))
              for (var o = 0; o < s; o++) {
                var c = (n[o >>> 2] >>> (24 - (o % 4) * 8)) & 255;
                r[(a + o) >>> 2] |= c << (24 - ((a + o) % 4) * 8);
              }
            else for (var o = 0; o < s; o += 4) r[(a + o) >>> 2] = n[o >>> 2];
            return (this.sigBytes += s), this;
          },
          clamp: function () {
            var r = this.words,
              n = this.sigBytes;
            (r[n >>> 2] &= 4294967295 << (32 - (n % 4) * 8)),
              (r.length = e.ceil(n / 4));
          },
          clone: function () {
            var e = o.clone.call(this);
            return (e.words = this.words.slice(0)), e;
          },
          random: function (r) {
            for (
              var n,
                a = [],
                s = function (r) {
                  var r = r,
                    n = 987654321;
                  return function () {
                    var a =
                      (((n = (36969 * (65535 & n) + (n >> 16)) & 4294967295) <<
                        16) +
                        (r = (18e3 * (65535 & r) + (r >> 16)) & 4294967295)) &
                      4294967295;
                    return (
                      (a /= 4294967296),
                      (a += 0.5) * (e.random() > 0.5 ? 1 : -1)
                    );
                  };
                },
                o = 0;
              o < r;
              o += 4
            ) {
              var u = s(4294967296 * (n || e.random()));
              (n = 987654071 * u()), a.push((4294967296 * u()) | 0);
            }
            return new c.init(a, r);
          },
        })),
        u = (a.enc = {}),
        l = (u.Hex = {
          stringify: function (e) {
            for (var r = e.words, n = e.sigBytes, a = [], s = 0; s < n; s++) {
              var o = (r[s >>> 2] >>> (24 - (s % 4) * 8)) & 255;
              a.push((o >>> 4).toString(16)), a.push((15 & o).toString(16));
            }
            return a.join("");
          },
          parse: function (e) {
            for (var r = e.length, n = [], a = 0; a < r; a += 2)
              n[a >>> 3] |= parseInt(e.substr(a, 2), 16) << (24 - (a % 8) * 4);
            return new c.init(n, r / 2);
          },
        }),
        p = (u.Latin1 = {
          stringify: function (e) {
            for (var r = e.words, n = e.sigBytes, a = [], s = 0; s < n; s++) {
              var o = (r[s >>> 2] >>> (24 - (s % 4) * 8)) & 255;
              a.push(String.fromCharCode(o));
            }
            return a.join("");
          },
          parse: function (e) {
            for (var r = e.length, n = [], a = 0; a < r; a++)
              n[a >>> 2] |= (255 & e.charCodeAt(a)) << (24 - (a % 4) * 8);
            return new c.init(n, r);
          },
        }),
        f = (u.Utf8 = {
          stringify: function (e) {
            try {
              return decodeURIComponent(escape(p.stringify(e)));
            } catch (r) {
              throw Error("Malformed UTF-8 data");
            }
          },
          parse: function (e) {
            return p.parse(unescape(encodeURIComponent(e)));
          },
        }),
        h = (s.BufferedBlockAlgorithm = o.extend({
          reset: function () {
            (this._data = new c.init()), (this._nDataBytes = 0);
          },
          _append: function (e) {
            "string" == typeof e && (e = f.parse(e)),
              this._data.concat(e),
              (this._nDataBytes += e.sigBytes);
          },
          _process: function (r) {
            var n,
              a = this._data,
              s = a.words,
              o = a.sigBytes,
              u = this.blockSize,
              l = o / (4 * u),
              p =
                (l = r ? e.ceil(l) : e.max((0 | l) - this._minBufferSize, 0)) *
                u,
              f = e.min(4 * p, o);
            if (p) {
              for (var h = 0; h < p; h += u) this._doProcessBlock(s, h);
              (n = s.splice(0, p)), (a.sigBytes -= f);
            }
            return new c.init(n, f);
          },
          clone: function () {
            var e = o.clone.call(this);
            return (e._data = this._data.clone()), e;
          },
          _minBufferSize: 0,
        }));
      s.Hasher = h.extend({
        cfg: o.extend(),
        init: function (e) {
          (this.cfg = this.cfg.extend(e)), this.reset();
        },
        reset: function () {
          h.reset.call(this), this._doReset();
        },
        update: function (e) {
          return this._append(e), this._process(), this;
        },
        finalize: function (e) {
          return e && this._append(e), this._doFinalize();
        },
        blockSize: 16,
        _createHelper: function (e) {
          return function (r, n) {
            return new e.init(n).finalize(r);
          };
        },
        _createHmacHelper: function (e) {
          return function (r, n) {
            return new d.HMAC.init(e, n).finalize(r);
          };
        },
      });
      var d = (a.algo = {});
      return a;
    })(Math);
function Arcfour() {
  (this.i = 0), (this.j = 0), (this.S = []);
}
function ARC4init(e) {
  var r, n, a;
  for (r = 0; r < 256; ++r) this.S[r] = r;
  for (r = 0, n = 0; r < 256; ++r)
    (n = (n + this.S[r] + e[r % e.length]) & 255),
      (a = this.S[r]),
      (this.S[r] = this.S[n]),
      (this.S[n] = a);
  (this.i = 0), (this.j = 0);
}
function ARC4next() {
  var e;
  return (
    (this.i = (this.i + 1) & 255),
    (this.j = (this.j + this.S[this.i]) & 255),
    (e = this.S[this.i]),
    (this.S[this.i] = this.S[this.j]),
    (this.S[this.j] = e),
    this.S[(e + this.S[this.i]) & 255]
  );
}
function prng_newstate() {
  return new Arcfour();
}
!(function (e) {
  var r = CryptoJS,
    n = r.lib,
    a = n.Base,
    s = n.WordArray,
    o = (r.x64 = {});
  (o.Word = a.extend({
    init: function (e, r) {
      (this.high = e), (this.low = r);
    },
  })),
    (o.WordArray = a.extend({
      init: function (e, r) {
        (e = this.words = e || []),
          void 0 != r ? (this.sigBytes = r) : (this.sigBytes = 8 * e.length);
      },
      toX32: function () {
        for (var e = this.words, r = e.length, n = [], a = 0; a < r; a++) {
          var o = e[a];
          n.push(o.high), n.push(o.low);
        }
        return s.create(n, this.sigBytes);
      },
      clone: function () {
        for (
          var e = a.clone.call(this),
            r = (e.words = this.words.slice(0)),
            n = r.length,
            s = 0;
          s < n;
          s++
        )
          r[s] = r[s].clone();
        return e;
      },
    }));
})(),
  (function (e) {
    var r = CryptoJS,
      n = r.lib,
      a = n.WordArray,
      s = n.Hasher,
      o = r.algo,
      c = a.create([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10,
        6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0,
        6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
      ]),
      u = a.create([
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0,
        13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8,
        12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10,
        14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
      ]),
      l = a.create([
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11,
        9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14,
        8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6,
        5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
      ]),
      p = a.create([
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7,
        12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12,
        13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12,
        5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
      ]),
      f = a.create([0, 1518500249, 1859775393, 2400959708, 2840853838]),
      h = a.create([1352829926, 1548603684, 1836072691, 2053994217, 0]),
      d = (o.RIPEMD160 = s.extend({
        _doReset: function () {
          this._hash = a.create([
            1732584193, 4023233417, 2562383102, 271733878, 3285377520,
          ]);
        },
        _doProcessBlock: function (e, r) {
          for (
            var n,
              a,
              s,
              o,
              d,
              _,
              $,
              y,
              g,
              v,
              C,
              E,
              S,
              T,
              B,
              I,
              A,
              b,
              N,
              R,
              k,
              L,
              U,
              D,
              w,
              P,
              x,
              V,
              O,
              K,
              F,
              M,
              H,
              G,
              j,
              q,
              z,
              Q,
              Y,
              W,
              X,
              J = 0;
            J < 16;
            J++
          ) {
            var Z = r + J,
              ee = e[Z];
            e[Z] =
              (((ee << 8) | (ee >>> 24)) & 16711935) |
              (((ee << 24) | (ee >>> 8)) & 4278255360);
          }
          var et = this._hash.words,
            er = f.words,
            ei = h.words,
            en = c.words,
            ea = u.words,
            es = l.words,
            eo = p.words;
          (q = F = et[0]),
            (z = M = et[1]),
            (Q = H = et[2]),
            (Y = G = et[3]),
            (W = j = et[4]);
          for (var J = 0; J < 80; J += 1)
            (X = (F + e[r + en[J]]) | 0),
              J < 16
                ? (X += ((n = M), (n ^ (a = H) ^ (s = G)) + er[0]))
                : J < 32
                ? (X += ((o = M), ((o & (d = H)) | (~o & (_ = G))) + er[1]))
                : J < 48
                ? (X += (($ = M), (($ | ~(y = H)) ^ (g = G)) + er[2]))
                : J < 64
                ? (X += ((v = M), (C = H), ((v & (E = G)) | (C & ~E)) + er[3]))
                : (X += ((S = M), (S ^ ((T = H) | ~(B = G))) + er[4])),
              (X |= 0),
              (X = ((X = m(X, es[J])) + j) | 0),
              (F = j),
              (j = G),
              (G = m(H, 10)),
              (H = M),
              (M = X),
              (X = (q + e[r + ea[J]]) | 0),
              J < 16
                ? (X += ((I = z), (I ^ ((A = Q) | ~(b = Y))) + ei[0]))
                : J < 32
                ? (X += ((N = z), (R = Q), ((N & (k = Y)) | (R & ~k)) + ei[1]))
                : J < 48
                ? (X += ((L = z), ((L | ~(U = Q)) ^ (D = Y)) + ei[2]))
                : J < 64
                ? (X += ((w = z), ((w & (P = Q)) | (~w & (x = Y))) + ei[3]))
                : (X += ((V = z), (V ^ (O = Q) ^ (K = Y)) + ei[4])),
              (X |= 0),
              (X = ((X = m(X, eo[J])) + W) | 0),
              (q = W),
              (W = Y),
              (Y = m(Q, 10)),
              (Q = z),
              (z = X);
          (X = (et[1] + H + Y) | 0),
            (et[1] = (et[2] + G + W) | 0),
            (et[2] = (et[3] + j + q) | 0),
            (et[3] = (et[4] + F + z) | 0),
            (et[4] = (et[0] + M + Q) | 0),
            (et[0] = X);
        },
        _doFinalize: function () {
          var e = this._data,
            r = e.words,
            n = 8 * this._nDataBytes,
            a = 8 * e.sigBytes;
          (r[a >>> 5] |= 128 << (24 - (a % 32))),
            (r[(((a + 64) >>> 9) << 4) + 14] =
              (((n << 8) | (n >>> 24)) & 16711935) |
              (((n << 24) | (n >>> 8)) & 4278255360)),
            (e.sigBytes = (r.length + 1) * 4),
            this._process();
          for (var s = this._hash, o = s.words, c = 0; c < 5; c++) {
            var u = o[c];
            o[c] =
              (((u << 8) | (u >>> 24)) & 16711935) |
              (((u << 24) | (u >>> 8)) & 4278255360);
          }
          return s;
        },
        clone: function () {
          var e = s.clone.call(this);
          return (e._hash = this._hash.clone()), e;
        },
      }));
    function _(e, r, n) {
      return e ^ r ^ n;
    }
    function $(e, r, n) {
      return (e & r) | (~e & n);
    }
    function y(e, r, n) {
      return (e | ~r) ^ n;
    }
    function g(e, r, n) {
      return (e & n) | (r & ~n);
    }
    function v(e, r, n) {
      return e ^ (r | ~n);
    }
    function m(e, r) {
      return (e << r) | (e >>> (32 - r));
    }
    (r.RIPEMD160 = s._createHelper(d)),
      (r.HmacRIPEMD160 = s._createHmacHelper(d));
  })(Math),
  (function () {
    var e = CryptoJS,
      r = e.lib,
      n = r.Base,
      a = r.WordArray,
      s = e.algo,
      o = s.MD5,
      c = (s.EvpKDF = n.extend({
        cfg: n.extend({ keySize: 4, hasher: o, iterations: 1 }),
        init: function (e) {
          this.cfg = this.cfg.extend(e);
        },
        compute: function (e, r) {
          for (
            var n,
              s = this.cfg,
              o = s.hasher.create(),
              c = a.create(),
              u = c.words,
              l = s.keySize,
              p = s.iterations;
            u.length < l;

          ) {
            n && o.update(n), (n = o.update(e).finalize(r)), o.reset();
            for (var f = 1; f < p; f++) (n = o.finalize(n)), o.reset();
            c.concat(n);
          }
          return (c.sigBytes = 4 * l), c;
        },
      }));
    e.EvpKDF = function (e, r, n) {
      return c.create(n).compute(e, r);
    };
  })(),
  CryptoJS.lib.Cipher ||
    (function (e) {
      var r = CryptoJS,
        n = r.lib,
        a = n.Base,
        s = n.WordArray,
        o = n.BufferedBlockAlgorithm,
        c = r.enc;
      c.Utf8;
      var u = c.Base64,
        l = r.algo.EvpKDF,
        p = (n.Cipher = o.extend({
          cfg: a.extend(),
          createEncryptor: function (e, r) {
            return this.create(this._ENC_XFORM_MODE, e, r);
          },
          createDecryptor: function (e, r) {
            return this.create(this._DEC_XFORM_MODE, e, r);
          },
          init: function (e, r, n) {
            (this.cfg = this.cfg.extend(n)),
              (this._xformMode = e),
              (this._key = r),
              this.reset();
          },
          reset: function () {
            o.reset.call(this), this._doReset();
          },
          process: function (e) {
            return this._append(e), this._process();
          },
          finalize: function (e) {
            return e && this._append(e), this._doFinalize();
          },
          keySize: 4,
          ivSize: 4,
          _ENC_XFORM_MODE: 1,
          _DEC_XFORM_MODE: 2,
          _createHelper: (function () {
            function e(e) {
              return "string" == typeof e ? m : g;
            }
            return function (r) {
              return {
                encrypt: function (n, a, s) {
                  return e(a).encrypt(r, n, a, s);
                },
                decrypt: function (n, a, s) {
                  return e(a).decrypt(r, n, a, s);
                },
              };
            };
          })(),
        }));
      n.StreamCipher = p.extend({
        _doFinalize: function () {
          return this._process(!0);
        },
        blockSize: 1,
      });
      var f = (r.mode = {}),
        h = (n.BlockCipherMode = a.extend({
          createEncryptor: function (e, r) {
            return this.Encryptor.create(e, r);
          },
          createDecryptor: function (e, r) {
            return this.Decryptor.create(e, r);
          },
          init: function (e, r) {
            (this._cipher = e), (this._iv = r);
          },
        })),
        d = (f.CBC = (function () {
          var e = h.extend();
          function r(e, r, n) {
            var a,
              s = this._iv;
            s ? ((a = s), (this._iv = void 0)) : (a = this._prevBlock);
            for (var o = 0; o < n; o++) e[r + o] ^= a[o];
          }
          return (
            (e.Encryptor = e.extend({
              processBlock: function (e, n) {
                var a = this._cipher,
                  s = a.blockSize;
                r.call(this, e, n, s),
                  a.encryptBlock(e, n),
                  (this._prevBlock = e.slice(n, n + s));
              },
            })),
            (e.Decryptor = e.extend({
              processBlock: function (e, n) {
                var a = this._cipher,
                  s = a.blockSize,
                  o = e.slice(n, n + s);
                a.decryptBlock(e, n),
                  r.call(this, e, n, s),
                  (this._prevBlock = o);
              },
            })),
            e
          );
        })()),
        _ = ((r.pad = {}).Pkcs7 = {
          pad: function (e, r) {
            for (
              var n = 4 * r,
                a = n - (e.sigBytes % n),
                o = (a << 24) | (a << 16) | (a << 8) | a,
                c = [],
                u = 0;
              u < a;
              u += 4
            )
              c.push(o);
            var l = s.create(c, a);
            e.concat(l);
          },
          unpad: function (e) {
            var r = 255 & e.words[(e.sigBytes - 1) >>> 2];
            e.sigBytes -= r;
          },
        });
      n.BlockCipher = p.extend({
        cfg: p.cfg.extend({ mode: d, padding: _ }),
        reset: function () {
          p.reset.call(this);
          var e,
            r = this.cfg,
            n = r.iv,
            a = r.mode;
          this._xformMode == this._ENC_XFORM_MODE
            ? (e = a.createEncryptor)
            : ((e = a.createDecryptor), (this._minBufferSize = 1)),
            this._mode && this._mode.__creator == e
              ? this._mode.init(this, n && n.words)
              : ((this._mode = e.call(a, this, n && n.words)),
                (this._mode.__creator = e));
        },
        _doProcessBlock: function (e, r) {
          this._mode.processBlock(e, r);
        },
        _doFinalize: function () {
          var e,
            r = this.cfg.padding;
          return (
            this._xformMode == this._ENC_XFORM_MODE
              ? (r.pad(this._data, this.blockSize), (e = this._process(!0)))
              : ((e = this._process(!0)), r.unpad(e)),
            e
          );
        },
        blockSize: 4,
      });
      var $ = (n.CipherParams = a.extend({
          init: function (e) {
            this.mixIn(e);
          },
          toString: function (e) {
            return (e || this.formatter).stringify(this);
          },
        })),
        y = ((r.format = {}).OpenSSL = {
          stringify: function (e) {
            var r,
              n = e.ciphertext,
              a = e.salt;
            return (r = a
              ? s.create([1398893684, 1701076831]).concat(a).concat(n)
              : n).toString(u);
          },
          parse: function (e) {
            var r,
              n = u.parse(e),
              a = n.words;
            return (
              1398893684 == a[0] &&
                1701076831 == a[1] &&
                ((r = s.create(a.slice(2, 4))),
                a.splice(0, 4),
                (n.sigBytes -= 16)),
              $.create({ ciphertext: n, salt: r })
            );
          },
        }),
        g = (n.SerializableCipher = a.extend({
          cfg: a.extend({ format: y }),
          encrypt: function (e, r, n, a) {
            a = this.cfg.extend(a);
            var s = e.createEncryptor(n, a),
              o = s.finalize(r),
              c = s.cfg;
            return $.create({
              ciphertext: o,
              key: n,
              iv: c.iv,
              algorithm: e,
              mode: c.mode,
              padding: c.padding,
              blockSize: e.blockSize,
              formatter: a.format,
            });
          },
          decrypt: function (e, r, n, a) {
            return (
              (a = this.cfg.extend(a)),
              (r = this._parse(r, a.format)),
              e.createDecryptor(n, a).finalize(r.ciphertext)
            );
          },
          _parse: function (e, r) {
            return "string" == typeof e ? r.parse(e, this) : e;
          },
        })),
        v = ((r.kdf = {}).OpenSSL = {
          execute: function (e, r, n, a) {
            a || (a = s.random(8));
            var o = l.create({ keySize: r + n }).compute(e, a),
              c = s.create(o.words.slice(r), 4 * n);
            return (o.sigBytes = 4 * r), $.create({ key: o, iv: c, salt: a });
          },
        }),
        m = (n.PasswordBasedCipher = g.extend({
          cfg: g.cfg.extend({ kdf: v }),
          encrypt: function (e, r, n, a) {
            var s = (a = this.cfg.extend(a)).kdf.execute(
              n,
              e.keySize,
              e.ivSize
            );
            a.iv = s.iv;
            var o = g.encrypt.call(this, e, r, s.key, a);
            return o.mixIn(s), o;
          },
          decrypt: function (e, r, n, a) {
            (a = this.cfg.extend(a)), (r = this._parse(r, a.format));
            var s = a.kdf.execute(n, e.keySize, e.ivSize, r.salt);
            return (a.iv = s.iv), g.decrypt.call(this, e, r, s.key, a);
          },
        }));
    })(),
  (function () {
    var e = CryptoJS,
      r = e.lib.BlockCipher,
      n = e.algo,
      a = [],
      s = [],
      o = [],
      c = [],
      u = [],
      l = [],
      p = [],
      f = [],
      h = [],
      d = [];
    !(function () {
      for (var e = [], r = 0; r < 256; r++)
        r < 128 ? (e[r] = r << 1) : (e[r] = (r << 1) ^ 283);
      for (var n = 0, _ = 0, r = 0; r < 256; r++) {
        var $ = _ ^ (_ << 1) ^ (_ << 2) ^ (_ << 3) ^ (_ << 4);
        ($ = ($ >>> 8) ^ (255 & $) ^ 99), (a[n] = $), (s[$] = n);
        var y = e[n],
          g = e[y],
          v = e[g],
          m = (257 * e[$]) ^ (16843008 * $);
        (o[n] = (m << 24) | (m >>> 8)),
          (c[n] = (m << 16) | (m >>> 16)),
          (u[n] = (m << 8) | (m >>> 24)),
          (l[n] = m);
        var m = (16843009 * v) ^ (65537 * g) ^ (257 * y) ^ (16843008 * n);
        (p[$] = (m << 24) | (m >>> 8)),
          (f[$] = (m << 16) | (m >>> 16)),
          (h[$] = (m << 8) | (m >>> 24)),
          (d[$] = m),
          n ? ((n = y ^ e[e[e[v ^ y]]]), (_ ^= e[e[_]])) : (n = _ = 1);
      }
    })();
    var _ = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54],
      $ = (n.AES = r.extend({
        _doReset: function () {
          if (!this._nRounds || this._keyPriorReset !== this._key) {
            for (
              var e,
                r = (this._keyPriorReset = this._key),
                n = r.words,
                s = r.sigBytes / 4,
                o = ((this._nRounds = s + 6) + 1) * 4,
                c = (this._keySchedule = []),
                u = 0;
              u < o;
              u++
            )
              u < s
                ? (c[u] = n[u])
                : ((e = c[u - 1]),
                  u % s
                    ? s > 6 &&
                      u % s == 4 &&
                      (e =
                        (a[e >>> 24] << 24) |
                        (a[(e >>> 16) & 255] << 16) |
                        (a[(e >>> 8) & 255] << 8) |
                        a[255 & e])
                    : ((e =
                        (a[(e = (e << 8) | (e >>> 24)) >>> 24] << 24) |
                        (a[(e >>> 16) & 255] << 16) |
                        (a[(e >>> 8) & 255] << 8) |
                        a[255 & e]),
                      (e ^= _[(u / s) | 0] << 24)),
                  (c[u] = c[u - s] ^ e));
            for (var l = (this._invKeySchedule = []), $ = 0; $ < o; $++) {
              var u = o - $;
              if ($ % 4) var e = c[u];
              else var e = c[u - 4];
              $ < 4 || u <= 4
                ? (l[$] = e)
                : (l[$] =
                    p[a[e >>> 24]] ^
                    f[a[(e >>> 16) & 255]] ^
                    h[a[(e >>> 8) & 255]] ^
                    d[a[255 & e]]);
            }
          }
        },
        encryptBlock: function (e, r) {
          this._doCryptBlock(e, r, this._keySchedule, o, c, u, l, a);
        },
        decryptBlock: function (e, r) {
          var n = e[r + 1];
          (e[r + 1] = e[r + 3]),
            (e[r + 3] = n),
            this._doCryptBlock(e, r, this._invKeySchedule, p, f, h, d, s);
          var n = e[r + 1];
          (e[r + 1] = e[r + 3]), (e[r + 3] = n);
        },
        _doCryptBlock: function (e, r, n, a, s, o, c, u) {
          for (
            var l = this._nRounds,
              p = e[r] ^ n[0],
              f = e[r + 1] ^ n[1],
              h = e[r + 2] ^ n[2],
              d = e[r + 3] ^ n[3],
              _ = 4,
              $ = 1;
            $ < l;
            $++
          ) {
            var y =
                a[p >>> 24] ^
                s[(f >>> 16) & 255] ^
                o[(h >>> 8) & 255] ^
                c[255 & d] ^
                n[_++],
              g =
                a[f >>> 24] ^
                s[(h >>> 16) & 255] ^
                o[(d >>> 8) & 255] ^
                c[255 & p] ^
                n[_++],
              v =
                a[h >>> 24] ^
                s[(d >>> 16) & 255] ^
                o[(p >>> 8) & 255] ^
                c[255 & f] ^
                n[_++],
              m =
                a[d >>> 24] ^
                s[(p >>> 16) & 255] ^
                o[(f >>> 8) & 255] ^
                c[255 & h] ^
                n[_++];
            (p = y), (f = g), (h = v), (d = m);
          }
          var y =
              ((u[p >>> 24] << 24) |
                (u[(f >>> 16) & 255] << 16) |
                (u[(h >>> 8) & 255] << 8) |
                u[255 & d]) ^
              n[_++],
            g =
              ((u[f >>> 24] << 24) |
                (u[(h >>> 16) & 255] << 16) |
                (u[(d >>> 8) & 255] << 8) |
                u[255 & p]) ^
              n[_++],
            v =
              ((u[h >>> 24] << 24) |
                (u[(d >>> 16) & 255] << 16) |
                (u[(p >>> 8) & 255] << 8) |
                u[255 & f]) ^
              n[_++],
            m =
              ((u[d >>> 24] << 24) |
                (u[(p >>> 16) & 255] << 16) |
                (u[(f >>> 8) & 255] << 8) |
                u[255 & h]) ^
              n[_++];
          (e[r] = y), (e[r + 1] = g), (e[r + 2] = v), (e[r + 3] = m);
        },
        keySize: 8,
      }));
    e.AES = r._createHelper($);
  })(),
  (CryptoJS.mode.ECB = (function () {
    var e = CryptoJS.lib.BlockCipherMode.extend();
    return (
      (e.Encryptor = e.extend({
        processBlock: function (e, r) {
          this._cipher.encryptBlock(e, r);
        },
      })),
      (e.Decryptor = e.extend({
        processBlock: function (e, r) {
          this._cipher.decryptBlock(e, r);
        },
      })),
      e
    );
  })()),
  (CryptoJS.pad.NoPadding = { pad: function () {}, unpad: function () {} }),
  (CryptoJS.mode.CTR = (function () {
    var e = CryptoJS.lib.BlockCipherMode.extend(),
      r = (e.Encryptor = e.extend({
        processBlock: function (e, r) {
          var n = this._cipher,
            a = n.blockSize,
            s = this._iv,
            o = this._counter;
          for (
            s && ((o = this._counter = s.slice(0)), (this._iv = void 0)),
              s = o.slice(0),
              n.encryptBlock(s, 0),
              o[a - 1] = (o[a - 1] + 1) | 0,
              n = 0;
            n < a;
            n++
          )
            e[r + n] ^= s[n];
        },
      }));
    return (e.Decryptor = r), e;
  })()),
  (function (e) {
    e.enc.Bin = {
      stringify: function (e) {
        for (var r = e.words, n = e.sigBytes, a = [], s = 0; n > s; s++)
          for (
            var o = (r[s >>> 2] >>> (24 - (s % 4) * 8)) & 255, c = 7;
            c >= 0;
            c--
          )
            a.push(((o >>> c) & 1).toString(2));
        return a.join("");
      },
      parse: function (r) {
        for (var n = [0], a = 31, s = 0, o = 0; o < r.length; o++) {
          var c = r[o];
          ("0" === c || "1" === c) &&
            ((n[n.length - 1] += parseInt(c) << a),
            a--,
            s++,
            0 > a && ((a = 31), n.push(0)));
        }
        return e.lib.WordArray.create(n, Math.ceil(s / 8));
      },
    };
  })(CryptoJS),
  (function (e) {
    var r;
    ((r = e.hasOwnProperty("ext") ? e.ext : (e.ext = {})).bitshift = function (
      e,
      r
    ) {
      var n,
        a,
        s = 0,
        o = e.words,
        c = 0;
      if (r > 0) {
        for (; r > 31; ) o.splice(0, 1), o.push(0), (r -= 32), c++;
        if (0 == r) return s;
        for (var u = o.length - c - 1; u >= 0; u--)
          (n = o[u]), (o[u] <<= r), (o[u] |= s), (s = n >>> (32 - r));
      } else if (0 > r) {
        for (; -31 > r; ) o.splice(0, 0, 0), o.length--, (r += 32), c++;
        if (0 == r) return s;
        a = (1 << (r = -r)) - 1;
        for (var u = c; u < o.length; u++)
          (n = o[u] & a), (o[u] >>>= r), (o[u] |= s), (s = n << (32 - r));
      }
      return s;
    }),
      (r.neg = function (e) {
        for (var r = e.words, n = 0; n < r.length; n++) r[n] = ~r[n];
        return e;
      }),
      (r.xor = function (e, r) {
        for (var n = 0; n < e.words.length; n++) e.words[n] ^= r.words[n];
        return e;
      }),
      (r.bitand = function (e, r) {
        for (
          var n = e.clone(), a = n.words, s = r.words, o = 0;
          o < a.length;
          o++
        )
          a[o] &= s[o];
        return n;
      });
  })(CryptoJS),
  (CryptoJS.mode.CFBw = (function () {
    function e(e, r, n) {
      for (
        var a = this,
          s = a._cipher,
          o = s.blockSize,
          c = a._prevBlock,
          u = s.cfg.segmentSize / 32,
          l = 0;
        o / u > l;
        l++
      ) {
        c
          ? (c = c.slice(u).concat(a._ct))
          : ((c = a._iv.slice(0)), (a._iv = void 0)),
          n || (a._ct = e.slice(r + l * u, r + l * u + u));
        var p = c.slice(0);
        s.encryptBlock(p, 0);
        for (var f = 0; u > f; f++) e[r + l * u + f] ^= p[f];
        n && (a._ct = e.slice(r + l * u, r + l * u + u));
      }
      a._prevBlock = c;
    }
    var r = CryptoJS.lib.BlockCipherMode.extend();
    return (
      (r.Encryptor = r.extend({
        processBlock: function (r, n) {
          e.call(this, r, n, !0);
        },
      })),
      (r.Decryptor = r.extend({
        processBlock: function (r, n) {
          e.call(this, r, n, !1);
        },
      })),
      r
    );
  })()),
  (function (e) {
    r = e.hasOwnProperty("ext") ? e.ext : (e.ext = {});
    var r,
      n = (e.lib.Base, e.lib.WordArray);
    e.algo.AES,
      (r.const_Zero = n.create([0, 0, 0, 0])),
      (r.const_One = n.create([0, 0, 0, 1])),
      (r.const_Rb = n.create([0, 0, 0, 135])),
      (r.const_Rb_Shifted = n.create([2147483648, 0, 0, 67])),
      (r.const_nonMSB = n.create([
        4294967295, 4294967295, 2147483647, 2147483647,
      ])),
      (r.isWordArray = function (e) {
        return (
          e &&
          "function" == typeof e.clamp &&
          "function" == typeof e.concat &&
          "array" == typeof e.words
        );
      }),
      (e.pad.OneZeroPadding = {
        pad: function (e, r) {
          for (
            var a = 4 * r, s = a - (e.sigBytes % a), o = [], c = 0;
            s > c;
            c += 4
          ) {
            var u = 0;
            0 === c && (u = 2147483648), o.push(u);
          }
          var l = n.create(o, s);
          e.concat(l);
        },
        unpad: function () {},
      }),
      (e.pad.NoPadding = { pad: function () {}, unpad: function () {} }),
      (r.leftmostBytes = function (e, r) {
        var n = e.clone();
        return (n.sigBytes = r), n.clamp(), n;
      }),
      (r.rightmostBytes = function (e, n) {
        e.clamp();
        var a = e.clone(),
          s = 8 * (a.sigBytes - n);
        if (s >= 32) {
          var o = Math.floor(s / 32);
          (s -= 32 * o), a.words.splice(0, o), (a.sigBytes -= (32 * o) / 8);
        }
        return s > 0 && (r.bitshift(a, s), (a.sigBytes -= s / 8)), a;
      }),
      (r.popWords = function (e, n) {
        var a = r.leftmostBytes(e, 4 * n);
        return (e.words = e.words.slice(n)), (e.sigBytes -= 4 * n), a;
      }),
      (r.shiftBytes = function (e, a) {
        var s = (a = a || 16) % 4;
        a -= s;
        for (var o = n.create(), c = 0; a > c; c += 4)
          o.words.push(e.words.shift()), (e.sigBytes -= 4), (o.sigBytes += 4);
        return (
          s > 0 &&
            (o.words.push(e.words[0]),
            (o.sigBytes += s),
            r.bitshift(e, 8 * s),
            (e.sigBytes -= s)),
          o
        );
      }),
      (r.xorendBytes = function (e, n) {
        return r
          .leftmostBytes(e, e.sigBytes - n.sigBytes)
          .concat(r.xor(r.rightmostBytes(e, n.sigBytes), n));
      }),
      (r.dbl = function (e) {
        var n = r.msb(e);
        return r.bitshift(e, 1), 1 === n && r.xor(e, r.const_Rb), e;
      }),
      (r.inv = function (e) {
        var n = 1 & e.words[4];
        return r.bitshift(e, -1), 1 === n && r.xor(e, r.const_Rb_Shifted), e;
      }),
      (r.equals = function (e, r) {
        if (!r || !r.words || e.sigBytes !== r.sigBytes) return !1;
        e.clamp(), r.clamp();
        for (var n = 0; n < e.words.length; n++)
          if (e.words[n] !== r.words[n]) return !1;
        return !0;
      }),
      (r.msb = function (e) {
        return e.words[0] >>> 31;
      });
  })(CryptoJS),
  (CryptoJS.mode.CFBb = (function () {
    function e(e, r, o) {
      var c,
        u,
        l,
        p = this,
        f = p._cipher,
        h = 32 * f.blockSize,
        d = p._prevBlock,
        _ = f.cfg.segmentSize,
        $ = [];
      for (c = 31; _ > c; c += 32) $.push(4294967295);
      for ($.push(((1 << _) - 1) << (32 - _)), c = $.length; c < e.length; c++)
        $.push(0);
      var y,
        g = ($ = n.create($)).clone(),
        v = g.clone();
      for (a(v, -(32 * r)), c = 0; h / _ > c; c++) {
        if (d) {
          for (
            a((d = n.create(d)), _),
              d = d.words,
              previousCiphertextSegment = p._ct;
            previousCiphertextSegment.length < h / 32;

          )
            previousCiphertextSegment.push(0);
          a(
            (previousCiphertextSegment = n.create(previousCiphertextSegment)),
            -h + _
          );
          for (var u = 0; u < d.length; u++)
            d[u] |= previousCiphertextSegment.words[u];
        } else (d = p._iv.slice(0)), (p._iv = void 0);
        l = 32 * r + c * _;
        var m = n.create(e.slice(0));
        a(m, l), o || (p._ct = m.words.slice(0, Math.ceil(_ / 32)));
        var C = d.slice(0);
        for (f.encryptBlock(C, 0), u = 0; u < Math.ceil(_ / 32); u++)
          m.words[u] ^= C[u];
        for (u = 0; u < m.words.length; u++) m.words[u] &= $.words[u];
        for (
          o && (p._ct = m.words.slice(0, Math.ceil(_ / 32))),
            y = s(v.clone()),
            u = 0;
          u < e.length;
          u++
        )
          e[u] &= y.words[u];
        for (a(m, -l), u = 0; u < e.length; u++) e[u] |= m.words[u];
        a(g, -_), a(v, -_);
      }
      p._prevBlock = d;
    }
    var r = CryptoJS.lib.BlockCipherMode.extend(),
      n = CryptoJS.lib.WordArray,
      a = CryptoJS.ext.bitshift,
      s = CryptoJS.ext.neg;
    return (
      (r.Encryptor = r.extend({
        processBlock: function (r, n) {
          e.call(this, r, n, !0);
        },
      })),
      (r.Decryptor = r.extend({
        processBlock: function (r, n) {
          e.call(this, r, n, !1);
        },
      })),
      r
    );
  })()),
  (function (e) {
    function r(r, n) {
      return s
        .createEncryptor(r, { iv: a.create(), padding: e.pad.NoPadding })
        .finalize(n);
    }
    var n = e.lib.Base,
      a = e.lib.WordArray,
      s = e.algo.AES,
      o = e.ext,
      c = e.pad.OneZeroPadding,
      u = (e.algo.CMAC = n.extend({
        init: function (e) {
          var n = r(e, o.const_Zero),
            a = n.clone();
          if ((o.dbl(a), this._isTwo())) {
            var s = n.clone();
            o.inv(s);
          } else {
            var s = a.clone();
            o.dbl(s);
          }
          (this._K1 = a),
            (this._K2 = s),
            (this._K = e),
            (this._const_Bsize = 16),
            this.reset();
        },
        reset: function () {
          (this._x = o.const_Zero.clone()),
            (this._counter = 0),
            (this._buffer = a.create());
        },
        update: function (n) {
          if (!n) return this;
          var a = this._buffer,
            s = this._const_Bsize;
          for (
            "string" == typeof n && (n = e.enc.Utf8.parse(n)), a.concat(n);
            a.sigBytes > s;

          ) {
            var c = o.shiftBytes(a, s);
            o.xor(this._x, c),
              this._x.clamp(),
              (this._x = r(this._K, this._x)),
              this._counter++;
          }
          return this;
        },
        finalize: function (e) {
          this.update(e);
          var n = this._buffer,
            a = this._const_Bsize,
            s = n.clone();
          return (
            n.sigBytes === a
              ? o.xor(s, this._K1)
              : (c.pad(s, a / 4), o.xor(s, this._K2)),
            o.xor(s, this._x),
            this.reset(),
            r(this._K, s)
          );
        },
        _isTwo: function () {
          return !1;
        },
      }));
    (e.CMAC = function (e, r) {
      return u.create(e).finalize(r);
    }),
      (e.algo.OMAC1 = u),
      (e.algo.OMAC2 = u.extend({
        _isTwo: function () {
          return !0;
        },
      }));
  })(CryptoJS),
  (function (e) {
    var r = e.lib.Base,
      n = e.lib.WordArray,
      a = (e.algo.AES, e.ext),
      s = e.pad.OneZeroPadding,
      o = e.algo.CMAC,
      c = (e.algo.S2V = r.extend({
        init: function (e) {
          (this._blockSize = 16),
            (this._cmacAD = o.create(e)),
            (this._cmacPT = o.create(e)),
            this.reset();
        },
        reset: function () {
          (this._buffer = n.create()),
            this._cmacAD.reset(),
            this._cmacPT.reset(),
            (this._d = this._cmacAD.finalize(a.const_Zero)),
            (this._empty = !0),
            (this._ptStarted = !1);
        },
        updateAAD: function (r) {
          return (
            this._ptStarted ||
              (r &&
                ("string" == typeof r && (r = e.enc.Utf8.parse(r)),
                (this._d = a.xor(a.dbl(this._d), this._cmacAD.finalize(r))),
                (this._empty = !1))),
            this
          );
        },
        update: function (r) {
          if (!r) return this;
          this._ptStarted = !0;
          var n = this._buffer,
            s = this._blockSize,
            o = s / 4,
            c = this._cmacPT;
          for (
            "string" == typeof r && (r = e.enc.Utf8.parse(r)), n.concat(r);
            n.sigBytes >= 2 * s;

          ) {
            this._empty = !1;
            var u = a.popWords(n, o);
            c.update(u);
          }
          return this;
        },
        finalize: function (e) {
          this.update(e);
          var r,
            n = this._blockSize,
            o = this._buffer;
          return this._empty && 0 === o.sigBytes
            ? this._cmacAD.finalize(a.const_One)
            : (o.sigBytes >= n
                ? (r = a.xorendBytes(o, this._d))
                : (s.pad(o, n), (r = a.xor(a.dbl(this._d), o))),
              this._cmacPT.finalize(r));
        },
      }));
    e.SIV = r.extend({
      init: function (e) {
        var r = e.sigBytes / 2;
        (this._s2vKey = a.shiftBytes(e, r)), (this._ctrKey = e);
      },
      encrypt: function (r, n) {
        !n && r && ((n = r), (r = []));
        var s = c.create(this._s2vKey);
        Array.prototype.forEach.call(r, function (e) {
          s.updateAAD(e);
        });
        var o = s.finalize(n),
          u = a.bitand(o, a.const_nonMSB),
          l = e.AES.encrypt(n, this._ctrKey, {
            iv: u,
            mode: e.mode.CTR,
            padding: e.pad.NoPadding,
          });
        return o.concat(l.ciphertext);
      },
      decrypt: function (r, n) {
        !n && r && ((n = r), (r = []));
        var s = a.shiftBytes(n, 16),
          o = a.bitand(s, a.const_nonMSB),
          u = e.AES.decrypt({ ciphertext: n }, this._ctrKey, {
            iv: o,
            mode: e.mode.CTR,
            padding: e.pad.NoPadding,
          }),
          l = c.create(this._s2vKey);
        Array.prototype.forEach.call(r, function (e) {
          l.updateAAD(e);
        });
        var p = l.finalize(u);
        return !!a.equals(s, p) && u;
      },
    });
  })(CryptoJS),
  (function (e) {
    var r = e.lib.Base,
      n = e.lib.WordArray,
      a = e.algo.AES,
      s = e.ext,
      o = e.algo.CMAC,
      c = n.create([0, 0, 0, 0]),
      u = n.create([0, 0, 0, 1]),
      l = n.create([0, 0, 0, 2]);
    e.EAX = r.extend({
      init: function (e, r) {
        var n;
        if (r && r.splitKey) {
          var a = Math.floor(e.sigBytes / 2);
          n = s.shiftBytes(e, a);
        } else n = e.clone();
        (this._ctrKey = e),
          (this._mac = o.create(n)),
          (this._tagLen = (r && r.tagLength) || 16),
          this.reset();
      },
      reset: function () {
        this._mac.update(u), this._ctr && this._ctr.reset();
      },
      updateAAD: function (e) {
        return this._mac.update(e), this;
      },
      initCrypt: function (r, o) {
        var u = this;
        return (
          (u._tag = u._mac.finalize()),
          (u._isEnc = r),
          u._mac.update(c),
          (o = u._mac.finalize(o)),
          s.xor(u._tag, o),
          (u._ctr = a.createEncryptor(u._ctrKey, {
            iv: o,
            mode: e.mode.CTR,
            padding: e.pad.NoPadding,
          })),
          (u._buf = n.create()),
          u._mac.update(l),
          u
        );
      },
      update: function (r) {
        "string" == typeof r && (r = e.enc.Utf8.parse(r));
        var a = this._buf,
          o = this._isEnc;
        a.concat(r);
        var c = o ? a.sigBytes : Math.max(a.sigBytes - this._tagLen, 0),
          u = c > 0 ? s.shiftBytes(a, c) : n.create(),
          l = this._ctr.process(u);
        return this._mac.update(o ? l : u), l;
      },
      finalize: function (e) {
        var r = e ? this.update(e) : n.create(),
          a = this._mac,
          o = this._ctr.finalize();
        if (this._isEnc) {
          var c = a.finalize(o);
          return (
            s.xor(this._tag, c), this.reset(), r.concat(o).concat(this._tag)
          );
        }
        var c = a.finalize();
        return (
          s.xor(this._tag, c),
          this.reset(),
          !!s.equals(this._tag, this._buf) && r.concat(o)
        );
      },
      encrypt: function (e, r, n) {
        var a = this;
        return (
          n &&
            Array.prototype.forEach.call(n, function (e) {
              a.updateAAD(e);
            }),
          a.initCrypt(!0, r),
          a.finalize(e)
        );
      },
      decrypt: function (e, r, n) {
        var a = this;
        return (
          n &&
            Array.prototype.forEach.call(n, function (e) {
              a.updateAAD(e);
            }),
          a.initCrypt(!1, r),
          a.finalize(e)
        );
      },
    });
  })(CryptoJS),
  (function (e) {
    var r = CryptoJS,
      n = r.lib,
      a = n.WordArray,
      s = n.Hasher,
      o = r.algo,
      c = [],
      u = [];
    !(function () {
      function r(r) {
        for (var n = e.sqrt(r), a = 2; a <= n; a++) if (!(r % a)) return !1;
        return !0;
      }
      function n(e) {
        return ((e - (0 | e)) * 4294967296) | 0;
      }
      for (var a = 2, s = 0; s < 64; )
        r(a) &&
          (s < 8 && (c[s] = n(e.pow(a, 0.5))),
          (u[s] = n(e.pow(a, 1 / 3))),
          s++),
          a++;
    })();
    var l = [],
      p = (o.SHA256 = s.extend({
        _doReset: function () {
          this._hash = new a.init(c.slice(0));
        },
        _doProcessBlock: function (e, r) {
          for (
            var n = this._hash.words,
              a = n[0],
              s = n[1],
              o = n[2],
              c = n[3],
              p = n[4],
              f = n[5],
              h = n[6],
              d = n[7],
              _ = 0;
            _ < 64;
            _++
          ) {
            if (_ < 16) l[_] = 0 | e[r + _];
            else {
              var $ = l[_ - 15],
                y =
                  (($ << 25) | ($ >>> 7)) ^
                  (($ << 14) | ($ >>> 18)) ^
                  ($ >>> 3),
                g = l[_ - 2],
                v =
                  ((g << 15) | (g >>> 17)) ^
                  ((g << 13) | (g >>> 19)) ^
                  (g >>> 10);
              l[_] = y + l[_ - 7] + v + l[_ - 16];
            }
            var m = (p & f) ^ (~p & h),
              C = (a & s) ^ (a & o) ^ (s & o),
              E =
                ((a << 30) | (a >>> 2)) ^
                ((a << 19) | (a >>> 13)) ^
                ((a << 10) | (a >>> 22)),
              S =
                d +
                (((p << 26) | (p >>> 6)) ^
                  ((p << 21) | (p >>> 11)) ^
                  ((p << 7) | (p >>> 25))) +
                m +
                u[_] +
                l[_],
              T = E + C;
            (d = h),
              (h = f),
              (f = p),
              (p = (c + S) | 0),
              (c = o),
              (o = s),
              (s = a),
              (a = (S + T) | 0);
          }
          (n[0] = (n[0] + a) | 0),
            (n[1] = (n[1] + s) | 0),
            (n[2] = (n[2] + o) | 0),
            (n[3] = (n[3] + c) | 0),
            (n[4] = (n[4] + p) | 0),
            (n[5] = (n[5] + f) | 0),
            (n[6] = (n[6] + h) | 0),
            (n[7] = (n[7] + d) | 0);
        },
        _doFinalize: function () {
          var r = this._data,
            n = r.words,
            a = 8 * this._nDataBytes,
            s = 8 * r.sigBytes;
          return (
            (n[s >>> 5] |= 128 << (24 - (s % 32))),
            (n[(((s + 64) >>> 9) << 4) + 14] = e.floor(a / 4294967296)),
            (n[(((s + 64) >>> 9) << 4) + 15] = a),
            (r.sigBytes = 4 * n.length),
            this._process(),
            this._hash
          );
        },
        clone: function () {
          var e = s.clone.call(this);
          return (e._hash = this._hash.clone()), e;
        },
      }));
    (r.SHA256 = s._createHelper(p)), (r.HmacSHA256 = s._createHmacHelper(p));
  })(Math),
  (Arcfour.prototype.init = ARC4init),
  (Arcfour.prototype.next = ARC4next);
var rng_psize = 256;
function rng_seed_int(e) {
  (rng_pool[rng_pptr++] ^= 255 & e),
    (rng_pool[rng_pptr++] ^= (e >> 8) & 255),
    (rng_pool[rng_pptr++] ^= (e >> 16) & 255),
    (rng_pool[rng_pptr++] ^= (e >> 24) & 255),
    rng_pptr >= rng_psize && (rng_pptr -= rng_psize);
}
function rng_seed_time() {
  rng_seed_int(new Date().getTime());
}
if (null == rng_pool) {
  for (t = 0, rng_pool = [], rng_pptr = 0; t < 32; ++t)
    rng_pool[rng_pptr++] = parseInt(1e10 * Math.random(), 10);
  for (; rng_pptr < rng_psize; )
    (t = Math.floor(65536 * Math.random())),
      (rng_pool[rng_pptr++] = t >>> 8),
      (rng_pool[rng_pptr++] = 255 & t);
  (rng_pptr = 0), rng_seed_time();
}
function rng_get_byte() {
  if (null == rng_state) {
    for (
      rng_seed_time(),
        (rng_state = prng_newstate()).init(rng_pool),
        rng_pptr = 0;
      rng_pptr < rng_pool.length;
      ++rng_pptr
    )
      rng_pool[rng_pptr] = 0;
    rng_pptr = 0;
  }
  return rng_state.next();
}
function rng_get_bytes(e) {
  var r;
  for (r = 0; r < e.length; ++r) e[r] = rng_get_byte();
}
function SecureRandom() {}
function xor(e, r) {
  var n,
    a = "";
  for (n = 0; n < e.length; n++)
    a += String.fromCharCode(parseInt(e.charCodeAt(n) ^ r.charCodeAt(n)));
  return a;
}
function createKey() {
  var e,
    r = "";
  for (e = 0; e < 32; e++)
    r += "0123456789ABCDEF"[Math.floor(16 * Math.random())];
  return r;
}
function createAAD() {
  var e,
    r = "";
  for (e = 0; e < 24; e++)
    r += "0123456789ABCDEF"[Math.floor(16 * Math.random())];
  return r;
}
function createIV() {
  var e,
    r = "";
  for (e = 0; e < 24; e++)
    r += "0123456789ABCDEF"[Math.floor(16 * Math.random())];
  return r;
}
function stringToHex(e) {
  for (
    var r = "",
      n = [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
      ],
      a = 0;
    a < e.length;
    a++
  )
    r += n[e.charCodeAt(a) >> 4] + n[15 & e.charCodeAt(a)];
  return r;
}
function hexToStringClear(e) {
  for (var r = "", n = "0x" == e.substr(0, 2) ? 2 : 0; n < e.length; n += 2)
    parseInt(e.substr(n, 2), 16) > 0 &&
      (r += String.fromCharCode(parseInt(e.substr(n, 2), 16)));
  return r;
}
function hexToString(e) {
  for (var r = "", n = "0x" == e.substr(0, 2) ? 2 : 0; n < e.length; n += 2)
    r += String.fromCharCode(parseInt(e.substr(n, 2), 16));
  return r;
}
function uint8ArrayToHex(e) {
  return Array.from(e)
    .map((e) => e.toString(16).padStart(2, "0"))
    .join("");
}
function hexToUint8Array(e) {
  let r = e.length / 2,
    n = new Uint8Array(r);
  for (let a = 0; a < r; a++) {
    let s = parseInt(e.substr(2 * a, 2), 16);
    n[a] = s;
  }
  return n;
}
function encryptKey(e, r) {
  var n = forge.pki
    .publicKeyFromPem(
      "-----BEGIN PUBLIC KEY-----\n" + e + "\n-----END PUBLIC KEY-----"
    )
    .encrypt(hexToString(r), "RSA-OAEP", {
      md: forge.md.sha512.create(),
      mgf1: { md: forge.md.sha512.create() },
    });
  return stringToHex(n).toUpperCase();
}
async function encryptPassword(e, r, n) {
  var a = await crypto.subtle.digest(
    "SHA-512",
    new TextEncoder("utf-8").encode(r + n)
  );
  return encryptKey(e, uint8ArrayToHex(new Uint8Array(a)));
}
async function encryptData(e, r) {
  var n = await crypto.subtle.importKey(
      "raw",
      hexToUint8Array(e),
      "AES-GCM",
      !0,
      ["encrypt", "decrypt"]
    ),
    a = createIV(),
    s = createAAD(),
    o = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: hexToUint8Array(a),
        additionalData: hexToUint8Array(s),
        tagLength: 128,
      },
      n,
      new TextEncoder().encode(r)
    ),
    c = uint8ArrayToHex(new Uint8Array(o)).toUpperCase(),
    u = uint8ArrayToHex(new Uint8Array(o.slice(c.length))).toUpperCase();
  return s + a + c + u;
}
async function decryptData(e, r) {
  var n = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: hexToUint8Array(r.substring(24, 48)),
      additionalData: hexToUint8Array(r.substring(0, 24)),
      tagLength: 128,
    },
    await crypto.subtle.importKey("raw", hexToUint8Array(e), "AES-GCM", !0, [
      "encrypt",
      "decrypt",
    ]),
    hexToUint8Array(r.substring(48))
  );
  return new TextDecoder().decode(new Uint8Array(n));
}
function hexToBase64(e) {
  return btoa(
    e
      .match(/\w{2}/g)
      .map(function (e) {
        return String.fromCharCode(parseInt(e, 16));
      })
      .join("")
  );
}
function createPadding() {
  var e,
    r = "";
  for (e = 0; e < 16; e++)
    r += "0123456789ABCDEF"[Math.floor(16 * Math.random())];
  return r;
}
function createKeyHSM() {
  var e,
    r = "";
  for (e = 0; e < 64; e++)
    r += "0123456789ABCDEF"[Math.floor(16 * Math.random())];
  return r;
}
function encryptKeyHSM(e, r, n) {
  if (512 != e.length) throw Error("Modulus Length Error");
  if (6 != r.length) throw Error("Exponent Length Error");
  var a = hexToBase64(
      "3082010A0282010100" + e.substring(0, 512) + "020" + r.length / 2 + r
    ),
    s = forge.pki
      .publicKeyFromPem(
        "-----BEGIN PUBLIC KEY-----\n" + a + "\n-----END PUBLIC KEY-----"
      )
      .encrypt(
        hexToString("302C0420" + n + "0408FC31C5E2705D3C5E"),
        "RSA-OAEP",
        { md: forge.md.sha512.create(), mgf1: { md: forge.md.sha512.create() } }
      );
  return stringToHex(s).toUpperCase();
}
function pinblokAES(e, r, n) {
  for (
    var a = CryptoJS.enc.Hex.parse("00000000000000000000000000000000"),
      s = "46" + n;
    s.length < 16;

  )
    s += "A";
  s += createPadding();
  for (
    var o = CryptoJS.AES.encrypt(CryptoJS.enc.Hex.parse(s), e, {
        iv: a,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding,
      })
        .toString()
        .toUpperCase(),
      c = "0" + r.substring(3, 15);
    c.length < 32;

  )
    c += "0";
  return stringToHex(xor(hexToString(o), hexToString(c)));
}
function encryptPIN(e, r, n, a) {
  var s = CryptoJS.enc.Hex.parse(createKeyHSM()),
    o = CryptoJS.enc.Hex.parse("00000000000000000000000000000000"),
    c = encryptKeyHSM(e, r, s);
  sMsg = pinblokAES(s, n, a);
  var u = CryptoJS.AES.encrypt(CryptoJS.enc.Hex.parse(sMsg), s, {
    iv: o,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
  })
    .toString()
    .toUpperCase();
  return c + u;
}
function encryptPINChange(e, r, n, a, s) {
  var o = CryptoJS.enc.Hex.parse(createKeyHSM()),
    c = CryptoJS.enc.Hex.parse("00000000000000000000000000000000"),
    u = encryptKeyHSM(e, r, o);
  sMsg = pinblokAES(o, n, a);
  var l = CryptoJS.AES.encrypt(CryptoJS.enc.Hex.parse(sMsg), o, {
    iv: c,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
  })
    .toString()
    .toUpperCase();
  sMsg = pinblokAES(o, n, s);
  var p = CryptoJS.AES.encrypt(CryptoJS.enc.Hex.parse(sMsg), o, {
    iv: c,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
  })
    .toString()
    .toUpperCase();
  return u + l + p;
}
function encryptMsg(e, r) {
  var n = CryptoJS.enc.Hex.parse(e),
    a = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
  if ((r = stringToHex(r)).length % 32 > 0)
    for (i = r.length % 32; i < 32; i++) r += "0";
  return CryptoJS.AES.encrypt(CryptoJS.enc.Hex.parse(r), n, {
    iv: a,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.NoPadding,
  })
    .toString()
    .toUpperCase();
}
function decryptMsg(e, r) {
  var n = CryptoJS.enc.Hex.parse(e),
    a = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
  return hexToStringClear(
    CryptoJS.AES.decrypt({ ciphertext: CryptoJS.enc.Hex.parse(r) }, n, {
      iv: a,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.NoPadding,
    }).toString()
  );
}
SecureRandom.prototype.nextBytes = rng_get_bytes;

