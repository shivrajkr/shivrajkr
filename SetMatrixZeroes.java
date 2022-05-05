Link : https://leetcode.com/problems/set-matrix-zeroes/

class Solution {
    public void setZeroes(int[][] matrix) {
        
       int rows = matrix.length;
        int col =matrix[0].length;
        int[][] alreadyTraversed=new int[rows][col];
        for(int i=0;i<rows;i++)
        {
            for(int j=0;j<col;j++)
            {
                if(matrix[i][j] == 0 && alreadyTraversed[i][j]!=1)
                {
                    setZero(matrix,i,j,rows,col,alreadyTraversed);
                    print(matrix,rows,col);
                    System.out.println("Alreadytraversed");
                    traversedprint(alreadyTraversed,rows,col);
                }
            }
        }
    }
    public void print(int[][] matrix,int rows, int col)
    {
        for(int i=0;i<rows;i++)
        {
            for(int j=0;j<col;j++)
            {
                System.out.print(matrix[i][j]+" ");
            }
            System.out.println();
        }
    }
    
    public void traversedprint(int[][] alreadyTraversed,int rows, int col)
    {
        for(int i=0;i<rows;i++)
        {
            for(int j=0;j<col;j++)
            {
                System.out.print(alreadyTraversed[i][j]+" ");
            }
            System.out.println();
        }
    }
    public void setZero(int[][] matrix,int row,int col,int rows,int cols,int[][] alreadyTraversed)
    {
        System.out.println("inside setZero and zero found in "+row+","+col);
        // Row makes zero
        for(int i=row;i<=row;i++)
        {
            for(int j=0;j<cols;j++)
            {
                System.out.println("inside row makes zero"+i+" "+j+" row "+row+" col "+col);
                if(matrix[i][j] == 0 && alreadyTraversed[i][j]!=1)
                {
                alreadyTraversed[i][j]=0;
                }
                else
                {
                matrix[i][j]=0;
                alreadyTraversed[i][j]=1;
                }
            }
        }
        // col makes zero 
        for(int i=0;i<rows;i++)
        {
            for(int j=col;j<=col;j++)
            {
                System.out.println("inside col makes zero"+i+" "+j+" row "+row+" col "+col);
                if(matrix[i][j] == 0 && alreadyTraversed[i][j]!=1)
                {
                alreadyTraversed[i][j]=0;
                }
                else
                {
                matrix[i][j]=0;
                alreadyTraversed[i][j]=1;
                }
            }
        }
        
        
    }
}


Time complexity : 0(n*m) + 0(n*m)    and  space complexity : 0(1)


class Solution {
    public void setZeroes(int[][] matrix) {
        
       int rows = matrix.length;
        int cols =matrix[0].length;
        int col0=1;
        for(int i=0;i<rows;i++)
        {
            if(matrix[i][0] == 0)
                {
                    col0=0;
                }
            for(int j=1;j<cols;j++)
            {
                
                if(matrix[i][j] == 0)
                {
                    matrix[0][j] = matrix[i][0] = 0;
                }
            }
        }
        
        
        for(int i=rows-1;i>=0;i--)
        {
            for(int j=cols-1;j>=1;j--)
            {
                if(matrix[i][0] == 0 || matrix[0][j] == 0)
                {
                    matrix[i][j]=0;
                }
            }
            if(col0==0) matrix[i][0]=0;
            
        }
        
}

}
