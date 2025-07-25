i=127
result='initial'
while [ ! -z $result ]
do
	i=$((i+1))
	result=$(/narnia/narnia2 $(python3 -c "print($i*'A')"))
done
echo "narnia2 crashes at $i"



