#! /bin/zsh

currentdate=$(date +%Y-%-m-%d\ %H:%M:%S)
git add .
git commit -m ${currentdate} 
git push origin master 

echo "****************************************Github上传完成****************************************"
