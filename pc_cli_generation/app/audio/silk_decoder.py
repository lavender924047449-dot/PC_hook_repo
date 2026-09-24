"""
SILK V3 → WAV 解码器 (Stage 4.5.5.1.7 语音扩展).

背景
====
PC 企业微信 `Cache/Voice/*.silk` 是 SILK V3 编码 (头字节 `\\x02#!SILK_V3`).
虚拟麦克风 (spike1 路径) 只吃 wav/mp3, 所以必须先转码.

管道
----
    silk  → (vendor/silk/silk_v3_decoder.exe)  → raw PCM (s16le, 24 kHz, mono)
    PCM   → (vendor/ffmpeg/ffmpeg.exe)         → WAV

产物默认落到 `runtime/silk_cache/<sha1_of_silk>.wav`, 天然幂等 (同 silk 同 wav).

不做的事
--------
* 不做 SILK → mp3 (要 lame; 我们不需要 mp3)
* 不做加密 silk 的解密 (企微本身没加密, 微信 amr 才有)
* 不并行解码 (多个文件一起转, 依然一个个来, 简单可靠)
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from app.config import resolve_path


# ---------------- 异常 ---------------- #

class SilkDecoderNotFound(RuntimeError):
    pass


class SilkDecodeError(RuntimeError):
    def __init__(self, msg: str, stderr: str = ""):
        super().__init__(msg)
        self.stderr = stderr


# ---------------- 主类 ---------------- #

class SilkDecoder:
    """
    典型用法::

        dec = SilkDecoder()                    # 自动找 vendor/ 下的 exe
        wav = dec.decode_to_cache("path/to/x.silk")
        # → runtime/silk_cache/<sha1>.wav  (幂等)

        # 或指定输出路径
        dec.decode("in.silk", "out.wav")
    """

    #: SILK 解码 exe (相对项目根)
    DEFAULT_SILK_EXE: str = "vendor/silk/silk_v3_decoder.exe"
    #: ffmpeg 用来把 raw PCM 封成 WAV
    DEFAULT_FFMPEG_EXE: str = "vendor/ffmpeg/ffmpeg.exe"
    #: silk_v3_decoder 默认输出 24 kHz mono s16le PCM
    DEFAULT_SAMPLE_RATE: int = 24000
    DEFAULT_CACHE_DIR: str = "runtime/silk_cache"

    def __init__(
        self,
        *,
        silk_exe: str | Path | None = None,
        ffmpeg_exe: str | Path | None = None,
        sample_rate: int = DEFAULT_SAMPLE_RATE,
    ) -> None:
        self.silk_exe = resolve_path(silk_exe or self.DEFAULT_SILK_EXE)
        self.ffmpeg_exe = resolve_path(ffmpeg_exe or self.DEFAULT_FFMPEG_EXE)
        self.sample_rate = int(sample_rate)

        if not self.silk_exe.is_file():
            raise SilkDecoderNotFound(
                f"silk_v3_decoder 不存在: {self.silk_exe}\n"
                f"请把 kn007/silk-v3-decoder 里的 silk_v3_decoder.exe 放到该路径 "
                f"(参见 vendor/silk/README.md)."
            )
        if not self.ffmpeg_exe.is_file():
            raise SilkDecoderNotFound(
                f"ffmpeg 不存在: {self.ffmpeg_exe}"
            )

    # ---------------- 单文件解码 ---------------- #

    def decode(
        self,
        silk_path: str | Path,
        wav_path: str | Path,
        *,
        keep_pcm: bool = False,
    ) -> Path:
        """
        silk → wav (通过临时 PCM 中转).
        wav_path 存在会被覆盖.
        """
        silk_p = Path(silk_path)
        if not silk_p.is_file():
            raise FileNotFoundError(f"silk 文件不存在: {silk_p}")
        wav_p = Path(wav_path)
        wav_p.parent.mkdir(parents=True, exist_ok=True)

        # 使用短临时路径规避旧版解码器在长路径下"rc=0 但无产物"的问题。
        workdir = Path(tempfile.mkdtemp(prefix="silk_decode_"))
        pcm_p = workdir / "decoded.pcm"
        wav_tmp = workdir / "decoded.wav"

        # ---- 1) silk → pcm ---- #
        cmd_silk = [str(self.silk_exe), str(silk_p), str(pcm_p)]
        logger.debug(f"silk_v3_decoder: {silk_p.name} → {pcm_p.name}")
        try:
            r = subprocess.run(
                cmd_silk, capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired as e:
            raise SilkDecodeError(f"silk_v3_decoder 超时 (>60s): {silk_p}") from e
        if r.returncode == 0 and not pcm_p.is_file():
            # 一些 silk 解码器版本会忽略第二个参数，把 PCM 落到输入同目录或当前工作目录。
            fallbacks = [
                silk_p.with_suffix(".pcm"),
                Path.cwd() / pcm_p.name,
                Path.cwd() / "output.pcm",
            ]
            for candidate in fallbacks:
                if candidate.is_file():
                    shutil.move(str(candidate), str(pcm_p))
                    break

        if r.returncode == 0 and not pcm_p.is_file():
            # 兜底：部分环境下 silk_v3_decoder 成功返回但未产出 PCM，尝试直接用 ffmpeg 解码 silk。
            cmd_ff_direct = [
                str(self.ffmpeg_exe),
                "-y",
                "-i",
                str(silk_p),
                "-ac",
                "1",
                "-ar",
                str(self.sample_rate),
                str(wav_tmp),
            ]
            r_direct = subprocess.run(
                cmd_ff_direct,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if r_direct.returncode == 0 and wav_tmp.is_file():
                shutil.move(str(wav_tmp), str(wav_p))
                logger.info(f"silk 直接 ffmpeg 解码完成: {silk_p.name} → {wav_p.name}")
                shutil.rmtree(workdir, ignore_errors=True)
                return wav_p

        if r.returncode != 0 or not pcm_p.is_file():
            raise SilkDecodeError(
                f"silk_v3_decoder 失败 (rc={r.returncode}): {silk_p}",
                stderr=(r.stderr or "") + (r.stdout or ""),
            )

        # ---- 2) pcm → wav ---- #
        cmd_ff = [
            str(self.ffmpeg_exe), "-y",
            "-f", "s16le", "-ar", str(self.sample_rate), "-ac", "1",
            "-i", str(pcm_p),
            str(wav_tmp),
        ]
        logger.debug(f"ffmpeg: {pcm_p.name} → {wav_p.name}")
        try:
            r = subprocess.run(
                cmd_ff, capture_output=True, text=True, timeout=60,
            )
        finally:
            if not keep_pcm and pcm_p.exists():
                try:
                    pcm_p.unlink()
                except OSError:
                    pass

        if r.returncode != 0 or not wav_tmp.is_file():
            raise SilkDecodeError(
                f"ffmpeg PCM→WAV 失败 (rc={r.returncode})",
                stderr=r.stderr or "",
            )

        shutil.move(str(wav_tmp), str(wav_p))
        if keep_pcm and pcm_p.is_file():
            keep_dst = wav_p.with_suffix(".pcm")
            keep_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(pcm_p), str(keep_dst))
        shutil.rmtree(workdir, ignore_errors=True)

        logger.info(
            f"silk 解码完成: {silk_p.name} → {wav_p.name} "
            f"({wav_p.stat().st_size} B)"
        )
        return wav_p

    # ---------------- 缓存式解码 ---------------- #

    def decode_to_cache(
        self,
        silk_path: str | Path,
        *,
        cache_dir: str | Path | None = None,
        force: bool = False,
    ) -> Path:
        """
        产物路径 = <cache_dir>/<sha1_of_silk>.wav.
        同 silk (同 sha1) 已经转过 → 直接返回旧 wav, 除非 force=True.
        """
        silk_p = Path(silk_path)
        if not silk_p.is_file():
            raise FileNotFoundError(f"silk 文件不存在: {silk_p}")

        cache = resolve_path(cache_dir or self.DEFAULT_CACHE_DIR)
        cache.mkdir(parents=True, exist_ok=True)

        sha = _sha1_of_file(silk_p)
        wav_p = cache / f"{sha}.wav"
        if wav_p.is_file() and not force:
            logger.debug(f"silk 缓存命中, 复用: {wav_p.name}")
            return wav_p

        return self.decode(silk_p, wav_p)


# ---------------- 工具 ---------------- #

def _sha1_of_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


__all__ = [
    "SilkDecoder",
    "SilkDecoderNotFound",
    "SilkDecodeError",
]
