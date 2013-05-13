find $1 -type d -print0 | while IFS= read -rd $'\0' f ; do echo "$f" ; done 

