import { Socket } from 'net';

/**
 * 检测 TCP 连接的第一个包是否为 HTTP 请求
 * @param firstChunk 第一个数据包
 * @returns 是否为 HTTP 请求
 */
export function isHttp(firstChunk: Buffer): boolean {
  if (!firstChunk || firstChunk.length === 0) {
    return false;
  }

  const str = firstChunk.toString('ascii', 0, Math.min(firstChunk.length, 16));
  
  // HTTP 请求方法
  const httpMethods = [
    'GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'TRACE ', 'CONNECT '
  ];
  
  return httpMethods.some(method => str.startsWith(method));
}

/**
 * 检测 TCP 连接的第一个包是否为 HTTPS 请求（TLS/SSL ClientHello）
 * @param firstChunk 第一个数据包
 * @returns 是否为 HTTPS 请求
 */
export function isHttps(firstChunk: Buffer): boolean {
  if (!firstChunk || firstChunk.length < 3) {
    return false;
  }

  // TLS/SSL ClientHello 的特征：
  // 第一个字节：0x16 (Handshake)
  // 第二个字节：0x03 (SSL 3.0/TLS 1.x)
  // 第三个字节：0x00-0x03 (版本号：SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3)
  return (
    firstChunk[0] === 0x16 &&
    firstChunk[1] === 0x03 &&
    firstChunk[2] >= 0x00 &&
    firstChunk[2] <= 0x04
  );
}

/**
 * 检测 TCP 连接的协议类型并调用相应的处理函数
 * @param socket TCP socket
 * @param httpHandler HTTP/HTTPS 处理函数
 * @param defaultHandler 默认处理函数（非 HTTP/HTTPS）
 * @param isHttpsMode 是否为 HTTPS 模式
 */
export function detectAndHandle(
  socket: Socket,
  httpHandler: (socket: Socket, firstChunk: Buffer) => void,
  defaultHandler: (socket: Socket) => void,
  isHttpsMode: boolean
): void {
  let firstDataReceived = false;

  const dataHandler = (chunk: Buffer) => {
    if (firstDataReceived) {
      return;
    }
    firstDataReceived = true;

    // 移除数据监听器，避免重复处理
    socket.removeListener('data', dataHandler);

    const isHttpRequest = isHttpsMode ? isHttps(chunk) : isHttp(chunk);

    if (isHttpRequest) {
      // 是 HTTP/HTTPS 请求，交给 HTTP 服务器处理
      // 需要把第一个数据包重新放回去
      socket.unshift(chunk);
      httpHandler(socket, chunk);
    } else {
      // 不是 HTTP/HTTPS 请求，交给默认处理器（YGOPro 协议）
      // 同样需要把第一个数据包重新放回去
      socket.unshift(chunk);
      defaultHandler(socket);
    }
  };

  socket.once('data', dataHandler);
}
