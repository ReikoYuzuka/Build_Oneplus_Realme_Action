#!/usr/bin/env python3
"""给 fs/proc/task_mmu.c 打上 SUSFS v2.4.0 需要的那几处钩子。

上游 50_add_susfs_in_gki-android15-6.6.patch 里 task_mmu.c 那一段的 hunk
行号是乱的（-275 出现在 -389 之后、-999 重复出现两次），在真我 6.6.89 树上
第 6 个 hunk 必然 fail。这里改成按锚点插入，幂等、可重复跑。
"""
import sys

PATH = "fs/proc/task_mmu.c"

INC = """#include <trace/hooks/mm.h>
#if defined(CONFIG_KSU_SUSFS_SUS_KSTAT) || defined(CONFIG_KSU_SUSFS_SUS_MAP) || defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)
#include <linux/susfs_def.h>
#endif // CONFIG_KSU_SUSFS_SUS_KSTAT || CONFIG_KSU_SUSFS_SUS_MAP || CONFIG_KSU_SUSFS_OPEN_REDIRECT
"""

EXTERN = """#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
extern void susfs_sus_kstat_spoof_show_map_vma(struct inode *inode, dev_t *out_dev, unsigned long *out_ino);
#endif // CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
extern struct srcu_struct susfs_srcu_open_redirect;
extern int susfs_open_redirect_spoof_show_map_vma_srcu(struct inode *inode, unsigned long *out_ino, dev_t *out_dev, char **out_spoofed_name);
#endif // CONFIG_KSU_SUSFS_OPEN_REDIRECT

static void
show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
{
"""

OLD_FILE_BLOCK = """	if (file) {
		struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	}
"""

NEW_FILE_BLOCK = """	if (file) {
		struct inode *inode = file_inode(vma->vm_file);
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		if (SUSFS_IS_INODE_OPEN_REDIRECT(inode)) {
			char *spoofed_redirected_name = NULL;
			int srcu_idx = srcu_read_lock(&susfs_srcu_open_redirect);
			int ret = susfs_open_redirect_spoof_show_map_vma_srcu(inode, &ino, &dev, &spoofed_redirected_name);
			if (!ret) {
				pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
				start = vma->vm_start;
				end = VMA_PAD_START(vma);
#ifdef __fold_filemap_fixup_entry
				__fold_filemap_fixup_entry(&((struct proc_maps_private *)m->private)->iter, &end);
#else
				if (flags & __VM_NO_COMPAT)
					return;
#endif
				show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino);
				seq_pad(m, ' ');
				if (spoofed_redirected_name)
					seq_puts(m, spoofed_redirected_name);
				seq_putc(m, '\\n');
				srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
				return;
			}
			srcu_read_unlock(&susfs_srcu_open_redirect, srcu_idx);
		}
#endif // CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
		if (SUSFS_IS_INODE_SUS_MAP(inode))
			return;
#endif // CONFIG_KSU_SUSFS_SUS_MAP
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		susfs_sus_kstat_spoof_show_map_vma(inode, &dev, &ino);
#endif // CONFIG_KSU_SUSFS_SUS_KSTAT
	}
"""

OLD_SMAP = """	struct vm_area_struct *vma = v;
	struct mem_size_stats mss;
"""

NEW_SMAP = """	struct vm_area_struct *vma = v;
	struct mem_size_stats mss;

#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	if (vma->vm_file) {
		if (SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))
			return 0;
	}
#endif // CONFIG_KSU_SUSFS_SUS_MAP
"""

OLD_LOOP = """	vma_start = vma->vm_start;
	do {
		smap_gather_stats(vma, &mss, 0);
		last_vma_end = vma->vm_end;
"""

NEW_LOOP = """	vma_start = vma->vm_start;
	do {
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
		if (vma->vm_file && SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))
			goto bypass_orig_flow;
#endif // CONFIG_KSU_SUSFS_SUS_MAP
		smap_gather_stats(vma, &mss, 0);
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
bypass_orig_flow:
#endif // CONFIG_KSU_SUSFS_SUS_MAP
		last_vma_end = vma->vm_end;
"""

OLD_CASE4 = """			/* Case 4 above */
			if (vma->vm_end > last_vma_end) {
				smap_gather_stats(vma, &mss, last_vma_end);
				last_vma_end = vma->vm_end;
			}
"""

NEW_CASE4 = """			/* Case 4 above */
			if (vma->vm_end > last_vma_end) {
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
				if (!vma->vm_file || !(SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file))))
					smap_gather_stats(vma, &mss, last_vma_end);
#else
				smap_gather_stats(vma, &mss, last_vma_end);
#endif // CONFIG_KSU_SUSFS_SUS_MAP
				last_vma_end = vma->vm_end;
			}
"""

EDITS = [
    ("include susfs_def.h", "#include <trace/hooks/mm.h>\n", INC),
    ("extern declarations",
     "static void\nshow_map_vma(struct seq_file *m, struct vm_area_struct *vma)\n{\n", EXTERN),
    ("show_map_vma body", OLD_FILE_BLOCK, NEW_FILE_BLOCK),
    ("show_smap guard", OLD_SMAP, NEW_SMAP),
    ("show_smaps_rollup loop", OLD_LOOP, NEW_LOOP),
    ("show_smaps_rollup case4", OLD_CASE4, NEW_CASE4),
]


def main():
    src = open(PATH, encoding="utf-8").read()

    if "susfs_def.h" in src:
        print("[SKIP] 已经打过 task_mmu 的 SUSFS 钩子，不重复插入")
        return 0

    for name, old, new in EDITS:
        n = src.count(old)
        if n != 1:
            print("::error::[%s] 锚点命中 %d 次（期望 1 次），中止" % (name, n))
            return 1
        src = src.replace(old, new, 1)
        print("[OK] %s" % name)

    open(PATH, "w", encoding="utf-8").write(src)

    chk = open(PATH, encoding="utf-8").read()
    for token in ("susfs_def.h", "susfs_sus_kstat_spoof_show_map_vma",
                  "susfs_open_redirect_spoof_show_map_vma_srcu",
                  "bypass_orig_flow", "SUSFS_IS_INODE_SUS_MAP"):
        if token not in chk:
            print("::error::写回后找不到 %s" % token)
            return 1
    print("[OK] task_mmu.c 的 SUSFS 钩子全部就位")
    return 0


if __name__ == "__main__":
    sys.exit(main())
