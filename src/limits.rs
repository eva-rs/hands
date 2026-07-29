//! Потолки и разрешения машины. Их задаёт хозяин машины, а не спрашивающий:
//! руки — последняя точка, где можно сказать «столько не отдам».

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Настройка демона. Уезжает клиенту в рукопожатии: зная потолки, он
/// откажет сам и не потащит по проводу то, что всё равно не примут.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Сколько байт отдаём за одно чтение.
    pub max_read: u64,
    /// Сколько байт принимаем за одну запись.
    pub max_write: u64,
    /// Потолок находок поиска и записей каталога за вызов.
    pub max_hits: u64,
    /// Сколько символов каждого потока вывода команды доезжает обратно.
    pub max_output: usize,
    /// Разрешено ли `exec`. Выключенные руки остаются файловыми.
    pub exec: bool,
    /// Таймаут команды, если спрашивающий не назвал свой.
    pub exec_timeout_secs: u64,
    /// Потолок таймаута: команда не должна висеть на машине вечно.
    pub exec_max_timeout_secs: u64,
    /// Разрешённые корни. Пусто — вся файловая система; ограничение
    /// лексическое (`..` разбирается, симлинки — нет), это грубая изгородь,
    /// а не песочница.
    pub roots: Vec<PathBuf>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_read: 64 * 1024 * 1024,
            max_write: 256 * 1024 * 1024,
            max_hits: 4096,
            max_output: 1024 * 1024,
            exec: true,
            exec_timeout_secs: 60,
            exec_max_timeout_secs: 3600,
            roots: Vec::new(),
        }
    }
}

impl Limits {
    /// Потолок тела кадра: и запись, и образец поиска, и stdin команды
    /// приезжают телом, а больший кадр читать незачем.
    pub fn max_frame(&self) -> u64 {
        self.max_write.max(self.max_read) + 64 * 1024
    }

    /// Лежит ли путь в разрешённых корнях.
    pub fn allows(&self, path: &Path) -> bool {
        self.roots.is_empty() || self.roots.iter().any(|root| path.starts_with(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_roots_means_the_whole_filesystem() {
        assert!(Limits::default().allows(Path::new("/etc/passwd")));
    }

    #[test]
    fn roots_fence_the_paths() {
        let limits = Limits { roots: vec!["/srv/games".into()], ..Limits::default() };
        assert!(limits.allows(Path::new("/srv/games/vn/data.arc")));
        assert!(!limits.allows(Path::new("/etc/passwd")));
        // сосед с общим началом имени — не внутри корня
        assert!(!limits.allows(Path::new("/srv/games-backup/x")));
    }
}
