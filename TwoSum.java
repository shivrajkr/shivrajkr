Link : https://leetcode.com/problems/two-sum/submissions/

My Solution : used two forloop Time :   and Space : 

  public int[] twoSum(int[] nums, int target) {
        for(int i=0;i<nums.length-1;i++)
        {
            for(int j=i+1;j<nums.length;j++)
            {
                if(nums[i]+nums[j] == target)
                {
                    return new int[]{i,j};
                }
            }
        }
        throws new IllegalArgumentException("No Match found");
    }

Time complexity reduces having 1 for loop : 

class Solution {
    public int[] twoSum(int[] nums, int target) {
        Map<Integer,Integer> map=new HashMap<>();
        for(int i=0;i<nums.length;i++)
        {
            int compliment=target - nums[i];
            if(map.containsKey(compliment))
            {
                return new int[]{map.get(compliment),i};
            }
            map.put(nums[i],i);
        }
        throw new IllegalArgumentException("No Match found");
    }
}
