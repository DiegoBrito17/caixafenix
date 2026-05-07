# PowerShell script to purge sensitive files using git-filter-repo
# Requires git-filter-repo (Python package) or the same tool installed.
# WARNING: This rewrites history; coordinate with collaborators before running.

$Files = @(
  'database/',
  'backups/',
  'ver_licencas.py',
  '*check*.html',
  '.env',
  '*.db'
)

Write-Host "This will rewrite git history and force-push to origin/main. Continue? (Y/N)"
$ans = Read-Host
if ($ans -ne 'Y' -and $ans -ne 'y') { Write-Host 'Aborting.'; exit 1 }

git branch backup-before-purge

$argList = @('--invert-paths')
foreach ($f in $Files) { $argList += '--paths'; $argList += $f }

# Invoke git-filter-repo
git filter-repo $argList

git push origin --force --all
git push origin --force --tags

Write-Host 'Purge complete. Inform collaborators to reclone the repo.'
