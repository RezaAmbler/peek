import {
  SiNginx,
  SiApache,
  SiMysql,
  SiPostgresql,
  SiRedis,
  SiMongodb,
  SiElasticsearch,
  SiRabbitmq,
  SiMariadb,
} from 'react-icons/si';
import {
  FaServer,
  FaDatabase,
  FaEnvelope,
  FaFolder,
  FaDesktop,
  FaGlobe,
  FaLock,
  FaTerminal,
} from 'react-icons/fa';
import { IconType } from 'react-icons';

interface ServiceIconProps {
  service: string;
  version?: string;
  className?: string;
  size?: number;
}

// Map service names to icons
const getServiceIcon = (service: string, version?: string): { icon: IconType; color: string } => {
  const s = service?.toLowerCase() || '';
  const v = version?.toLowerCase() || '';

  // Check version string first (more specific)
  if (v.includes('nginx')) {
    return { icon: SiNginx, color: '#009639' };
  }
  if (v.includes('apache')) {
    return { icon: SiApache, color: '#D22128' };
  }
  if (v.includes('openssh') || v.includes('ssh')) {
    return { icon: FaTerminal, color: '#231F20' };
  }
  if (v.includes('mysql')) {
    return { icon: SiMysql, color: '#4479A1' };
  }
  if (v.includes('mariadb')) {
    return { icon: SiMariadb, color: '#003545' };
  }
  if (v.includes('postgresql') || v.includes('postgres')) {
    return { icon: SiPostgresql, color: '#4169E1' };
  }
  if (v.includes('redis')) {
    return { icon: SiRedis, color: '#DC382D' };
  }
  if (v.includes('mongodb') || v.includes('mongo')) {
    return { icon: SiMongodb, color: '#47A248' };
  }
  if (v.includes('elasticsearch') || v.includes('elastic')) {
    return { icon: SiElasticsearch, color: '#005571' };
  }
  if (v.includes('rabbitmq')) {
    return { icon: SiRabbitmq, color: '#FF6600' };
  }
  if (v.includes('memcached')) {
    return { icon: FaDatabase, color: '#00897B' };
  }
  if (v.includes('dovecot') || v.includes('postfix') || v.includes('exim')) {
    return { icon: FaEnvelope, color: '#1565C0' };
  }
  if (v.includes('vsftpd') || v.includes('proftpd') || v.includes('pure-ftpd')) {
    return { icon: FaFolder, color: '#FFA000' };
  }

  // Check service name
  if (s.includes('nginx') || (s === 'http' && v.includes('nginx'))) {
    return { icon: SiNginx, color: '#009639' };
  }
  if (s.includes('apache') || (s === 'http' && v.includes('apache'))) {
    return { icon: SiApache, color: '#D22128' };
  }
  if (s === 'ssh' || s.includes('openssh')) {
    return { icon: FaTerminal, color: '#231F20' };
  }
  if (s === 'mysql' || s.includes('mysql')) {
    return { icon: SiMysql, color: '#4479A1' };
  }
  if (s === 'mariadb' || s.includes('mariadb')) {
    return { icon: SiMariadb, color: '#003545' };
  }
  if (s === 'postgresql' || s.includes('postgres')) {
    return { icon: SiPostgresql, color: '#4169E1' };
  }
  if (s === 'redis' || s.includes('redis')) {
    return { icon: SiRedis, color: '#DC382D' };
  }
  if (s === 'mongodb' || s.includes('mongo')) {
    return { icon: SiMongodb, color: '#47A248' };
  }
  if (s === 'elasticsearch' || s.includes('elastic')) {
    return { icon: SiElasticsearch, color: '#005571' };
  }
  if (s === 'amqp' || s.includes('rabbitmq')) {
    return { icon: SiRabbitmq, color: '#FF6600' };
  }
  if (s === 'memcached' || s.includes('memcache')) {
    return { icon: FaDatabase, color: '#00897B' };
  }
  if (s === 'ftp' || s === 'ftps') {
    return { icon: FaFolder, color: '#FFA000' };
  }
  if (s === 'imap' || s === 'imaps' || s === 'pop3' || s === 'pop3s' || s === 'smtp' || s === 'smtps' || s.includes('mail')) {
    return { icon: FaEnvelope, color: '#1565C0' };
  }
  if (s === 'ms-wbt-server' || s.includes('rdp') || s === 'msrdp') {
    return { icon: FaDesktop, color: '#0078D4' };
  }
  if (s.includes('http') || s === 'www' || s === 'https') {
    return { icon: FaGlobe, color: '#4CAF50' };
  }

  // Default
  return { icon: FaServer, color: '#757575' };
};

// Check if SSL/TLS service
const isSecure = (service: string): boolean => {
  const s = service?.toLowerCase() || '';
  return s.startsWith('ssl/') || s.startsWith('tls/') || s.includes('https') ||
         s === 'imaps' || s === 'pop3s' || s === 'smtps' || s === 'ftps';
};

export function ServiceIcon({
  service,
  version,
  className = '',
  size = 20
}: ServiceIconProps) {
  const { icon: Icon, color } = getServiceIcon(service, version);
  const secure = isSecure(service);

  return (
    <div className={`relative inline-flex items-center ${className}`} data-testid="service-icon">
      <Icon size={size} style={{ color }} />
      {secure && (
        <FaLock
          size={size * 0.5}
          className="absolute -bottom-1 -right-1 text-green-600"
          title="SSL/TLS"
        />
      )}
    </div>
  );
}

export default ServiceIcon;
